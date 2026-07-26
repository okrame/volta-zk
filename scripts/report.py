#!/usr/bin/env python3
"""P7 report and GPU/communication budget model.

This is intentionally a reporting layer over benchmark JSONs. It does not
change proving parameters, transcript layout, PCS openings, or soundness
assumptions. PCS alternatives are projections from the checked
`MultiOpenProof::bytes()` formula.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import platform
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO / "benchmarks" / "results"
P7_RHO_TARGETS = {"prefill": 10.0, "decode": 2.0}
P7B_REPORT_SCHEMA_VERSION = 6
P7B_CUDA_ABI_VERSION = 28
P7B_OFFICIAL_RESIDENT_TIMING_POLICY = "wall-only-counters"
P7B_OFFICIAL_SESSION_TIMING_METHOD = "wall-only-counters"
P7B_GATE_PROFILE = "runpod-a100-v1"
P7B_OFFICIAL_RAYON_THREADS = 8
P7B_PREFILL_CORE_GATE_S = 10.0
P7B_DECODE_MARGINAL_GATE_S = 4.0
P7B_SYNC_WALL_FRACTION_GATE = 0.02
P7B_H2D_GATE_BYTES = 100_000_000
P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES = 200_000_000
P7B_TRANSCRIPT_REFERENCE_BYTES = 137_413_808
P7B_PCS_OPENING_REFERENCE_BYTES = 66_733_504
P7B_PACKED_LOGITS_REFERENCE_BYTES = 7_407_122
P7B_PACKED_RESPONSE_REFERENCE_BYTES = 144_820_930
FASE_D_POD_REPORT_SCHEMA_VERSION = 7
FASE_D_POD_GATE_PROFILE_V1 = "runpod-a100-realpcg-v1"
FASE_D_POD_GATE_PROFILE_V2 = "runpod-a100-realpcg-v2"
FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S = 0.150
C3B_REPORT_SCHEMA_VERSION = 9
C3B_POD_GATE_PROFILE = "runpod-a100-realpcg-v3"
C3B_TRANSCRIPT_REFERENCE_BYTES = 105_717_632
C3B_PCS_OPENING_REFERENCE_BYTES = 43_273_888
C3B_PACKED_RESPONSE_GATE_BYTES = 115_000_000
C3B_L4_TRANSCRIPT_BYTES = 57_840
C3B_LIMBS = 3
C3B_RANGE_INSTANCES = 6
C3B_REAL_COMPARISONS = 2_512_850
C3B_PACKED_ENTRIES_PER_LIMB = (1 << 21) + (1 << 19)
C3B_PACKED_ENTRIES_TOTAL = C3B_LIMBS * C3B_PACKED_ENTRIES_PER_LIMB
C3B_L4_EMULT_INSTANCES = 157_705_530.0
C3B_L4_EMULT_CEILING = 260_000_000.0
C3B_EMULT_INSTANCES_TOTAL = 2_775_723_398.8
C3B_G2_POD_BASELINE_S = 4.911_634
C3B_G2_POD_CEILING_S = 5.648_379_1
T1_REPORT_SCHEMA_VERSION = 10
T1_POD_GATE_PROFILE = "runpod-a100-realpcg-v4"
T1_RESPONSE_GATE_BYTES = 85_000_000
T1_RESPONSE_REFERENCE_BYTES = 84_544_352
T1_AUTH_CORRECTION_REFERENCE_BYTES = 38_348_720
T1_EQ_REDUCER_TRANSCRIPT_BYTES = 22_848
T1_Q_BRIDGE_CORRECTION_BYTES = 672
T1_SUB_CORRS = 4_793_590
T1_FULL_CORRS = 181_933
T1_PROD_CLAIMS = 21_667
T1_ZERO_CLAIMS = 8_170
T1_EMULT_INSTANCES_TOTAL = 2_800_595_736.8
T1_EMULT_OTHER_TOTAL = 114_852_961.2
P7B_TIMING_STATISTIC = "upper median across measured repetitions"
P7B_COUNTER_STATISTIC = "maximum across measured sessions"
C1_REPORT_SCHEMA_VERSION = 3
C1_TRANSCRIPT_REFERENCE_BYTES = 129_119_408
C1_AUTH_CORRECTION_REFERENCE_BYTES = 59_545_008
C1_PCS_OPENING_REFERENCE_BYTES = 66_733_504
C1_PACKED_LOGITS_REFERENCE_BYTES = 7_407_122
C1_PACKED_RESPONSE_REFERENCE_BYTES = 136_526_530
C1_IDENTITY_SEAM_ALIAS_VALUES = 1_036_800
C1_SUB_CORR_REFERENCE = 7_443_126
C1_FULL_CORR_REFERENCE = 176_880
X4_V4_PROFILE = "x4-zkdeepfold-ud-e29-v4"
X4_V4_DESIGN_SHA256 = (
    "c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544"
)
X4_V4_SOUNDNESS_EXPRESSION = (
    "3320*(9/16)^111 + "
    "28522064267253/340282366762482138490186164457219031041"
)
X4_V4_SOUNDNESS_BITS = 80.25537016399041
X4_V4_SOUNDNESS_FLOOR_BITS = 78.809294874
X4_V4_PACKED_OPENING_BYTES = 2_615_414
X4_V4_PCS_BYTES = 2_683_236
X4_V4_RESPONSE_BYTES = 43_953_700
X4C_GPT2_MODEL_TRANSCRIPT_PROVER_BYTES = X4_V4_RESPONSE_BYTES - X4_V4_PCS_BYTES - 64
X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_BYTES = 41_034_112
X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_LABELS = 25
X4_V4_POD_PROFILE = "runpod-a100-x4-v1"
X4_V4_FROZEN_BASELINE_SHA256 = (
    "1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7"
)
X4_V4_MIGRATION_SHA256 = (
    "d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e"
)
X4_V4_NOTE6_SHA256 = (
    "8fef35aae0412c45556b37fbfba89c88041d9de8b3c9733ad65227daeb83b0c2"
)
X4_V4_SOURCE_FLOOR_BYTES = 31_923_699_712
X4_V4_PHYSICAL_ORACLE_BYTES = 76_948_701_184
X4_V4_COEFFICIENT_BYTES = 9_618_587_648
X4_V4_INNER_MERKLE_DIGESTS = 12_333_875_200
X4_V4_OUTER_MERKLE_DIGESTS = 2_318_401_531
X4_V4_MERKLE_BYTES = 468_872_855_392
X4_V4_MATERIALIZATION_BYTES = 545_821_556_576
X4_V4_RESPONSE_RECOMPUTE_BYTES = 1_091_643_113_152
X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES = 9_618_587_808
X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES = 363_998_478_304
X4_V4_COUNTER_FAMILIES = [
    "frame_reject",
    "packed_schedule_reject",
    "packed_reconstruction_reject",
    "cohort_binding_reject",
    "slot_identity_reject",
    "early_query_reject",
    "accepted_unsealed_chain",
    "fold_query_bad",
    "claim_reduce_bad",
    "auth_link_bad",
    "response_zero_batch_bad",
    "pending_escape_reject",
    "target_eval_leak_reject",
    "correlation_view_reject",
    "epoch_reuse_reject",
    "delta_shift_attempt",
    "beta_collision_witness",
]
X4D_CODEC_REFERENCE_MILESTONE = "X4d-Phase2-local-codec-reference"
X4D_PROFILE = "x4-zkdeepfold-ud-e29-x4d-v1"
X4D_CODEC_SOURCE_GIT_SHA = "16e6c40b6620e09363a8c53eb3ecc632fa650f25"
X4D_DESIGN_SHA256 = (
    "405f3362a45f3d753d65827cdd48aacef2ec0b5c6d00c9f2b450129ad5b36fe8"
)
X4D_CODEC_GENERATOR_SHA256 = (
    "95729dc166c2eb292efb570ada9410ac4edac97bb93859ff7b527c411be37bae"
)
X4D_FROZEN_PREFLIGHT_SHA256 = (
    "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499"
)
X4D_RESPONSE_BYTES = 41_270_464
X4D_SETTLEMENT_REFERENCES = (
    (
        1,
        2_683_236,
        "fc5158b3bdd380df6e9d20657b3475fc386f797c151f0f7c214a216e91c356e5",
    ),
    (
        8,
        3_036_204,
        "81355cb2430d289769ec43c43d4a1ad3833f2f4180609b264bef589bc96b043f",
    ),
    (
        16,
        3_439_596,
        "62839bbbe8bf494fa2267bf3d486c094a3b51b7eab56e11123f088731eac6221",
    ),
    (
        32,
        4_246_380,
        "f7df30cddf241143db520c47fb29d9cd4b00b364a33e926d4e7c9a4d88e4739c",
    ),
)
X4D_CODEC_AMENDMENT_MILESTONE = "X4d-Phase3-fresh-query-codec-amendment-1"
X4D_CODEC_AMENDMENT_SOURCE_GIT_SHA = "4efa5f65ca6948fc0028ce74570943d7f6596f6d"
X4D_CODEC_AMENDMENT_DESIGN_SHA256 = (
    "61be8d68df8cd5482cd815b855fd2fc417bbc3c14b2a0d20dadbe2c479816451"
)
X4D_CODEC_AMENDMENT_GENERATOR_SHA256 = (
    "e80b142faeccd76030e72e5ae59b7d92b9365391bd02de4e63683530a49fcd82"
)
X4D_CODEC_AMENDMENT_SEMANTICS = (
    "fresh settlement queries retain their registered distribution; the variable "
    "canonical Merkle frontier is bounded componentwise and the X4d envelope is "
    "padded with verified zeros to the fixed wire maximum"
)
X4D_CODEC_AMENDMENT_REFERENCES = (
    (
        1,
        2_808_420,
        "a81a246cbbb3f0bfb29870563931f4f384e428ca3c38549be43f52a31b22d23c",
    ),
    (
        8,
        3_161_388,
        "082b3ba66a6450ba4256576b0361f9e94651c79a23e1a227b0c2a213ea80ff1f",
    ),
    (
        16,
        3_564_780,
        "33df9833b62692d0d81e32b68991894079995ce6f6cacd5857be53548f067dbd",
    ),
    (
        32,
        4_371_564,
        "42e1e28e7db5d6df0a86344129be70a5b25656cca9980fc4a7ba8e15467558ab",
    ),
)
X4D_PHASE3_PROFILE = "runpod-a100-x4d-v1"
X4D_PHASE3_PROTOCOL = "x4-zkdeepfold-ud-e29-v4+x4d-deferred-settlement-v1"
X4D_PHASE3_DESIGN_SHA256 = (
    "0f60edfc121978d5ce5411904cff766d46d8a4aa6d3eb860f92e13e535e9da12"
)
X4D_PHASE3_PRODUCER_SHA256 = (
    "a6ea3b4620ab8fa4966d78e9070317030e7a5a4bb082de6e2da19545726db429"
)
X4D_PHASE3_PREFLIGHT_MILESTONE = "X4d-GPT2-pod-preflight-v1"
X4D_PHASE3_ONLINE_MILESTONE = "X4d-GPT2-real-weight-deferred-settlement-v1"
X4D_SOUNDNESS_EXPRESSION = "3320*(9/16)^111 + 28,522,064,267,253/|E|"
X4D_SOUNDNESS_BITS = 80.25537016399041
X4D_PHASE3_SETTLED_RESPONSES = 16
X4D_PHASE3_CONNECTION_RESPONSES = 19
X4D_PHASE3_SETTLEMENT_BYTES = 3_564_780
X4D_PHASE3_G2_TESTS = [
    "post_freeze_value_substitution_is_rejected_by_m2_mac",
    "accumulator_roles_match_and_omission_reorder_mismatch",
    "exact_range_rejects_subset_reorder_and_replay",
    "x4d_delivery_without_freeze_and_wrong_settlement_subset_burn_connection",
    "x4d_settlement_freshness_is_required_before_success_and_is_one_use",
]
X4D1_FLATNESS_MILESTONE = "X4d.1-GPT2-flatness-gate-v1"
X4D1_DESIGN_SHA256 = (
    "3ca7b497d3604c220a2de59ceb1279172dc8bd8e835081900b3cfc17fe3af463"
)
X4D1_FLATNESS_PRODUCER_SHA256 = (
    "d7adf10afb9ab8a8d3aa934dced519784e51fa950937536b732dfd6a0b422b0d"
)
X4D1_WALL_SEMANTICS = (
    "durable accumulator seal through terminal settlement success, including "
    "queued-response priority pause and fresh auxiliary materialization"
)
X4D1_FLATNESS_CEILING = 1.30
X4D1_INTERFERENCE_CEILING_PERCENT = 1.00
X4D1_INITIAL_ENCODED_SYMBOLS = 4_809_293_824
X4D1_COMBINED_CODEWORD_SYMBOLS = 1_159_200_768
X4D1_RESPONSE_BYTES = 41_270_464
X4B_DESIGN_SHA256 = (
    "bc057e458041e8123e3ef065d22b74573bcb7238a8dcee239bccfa0e8ff6be01"
)
X4B_POD_PROFILE = "runpod-a100-x4b-v1"
X4B_QUERY_TAPE_BLAKE3 = (
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299"
)
X4B_CPU_CANONICAL_BYTES = 460_324_760
X4B_CPU_HASH_CALLS = 5_242_879
X4B_CPU_GATE_BPS = 500_000_000.0
X4B_OPEN_CEILING_S = 1.50
X4B_VERIFY_CEILING_S = 0.25
X4B_COMMIT_CEILING_S = 15.0
X4B_DURABLE_BYTES = 86_567_288_992
X4B_FULL_INITIAL_CACHE_BYTES = 37_094_424_416
X4B_DEGRADED_INITIAL_CACHE_BYTES = 18_547_212_128
X4B_FULL_FOLD_CACHE_BYTES = 34_359_737_248
X4B_DEGRADED_FOLD_CACHE_BYTES = 17_179_868_192
X4B_DEVICE_BYTE_CEILING = 48 * 1024 * 1024 * 1024
X4B_MIN_VOLUME_BYTES = 150_000_000_000
X4B_BASELINE_RAM_BYTES = 128 * 1024 * 1024 * 1024
X4C_PREREGISTRATION_V1_SHA256 = (
    "7d4f8254b066b91fea9ee52fbef0f0008632adccceef1513d3d3478eeea3a52a"
)
X4C_DESIGN_SHA256 = (
    "1a744625078e3ffe5772b040c24854e9510dcedebc906416279cf3a7c29bf191"
)
X4C_PHASE1_MILESTONE = "X4c-phase1-open-lifecycle-postdiction"
X4C_SYNTHETIC_DOMAIN_LOG2 = [16, 18, 20, 22]
X4C_MEASURED_CANDIDATES = 5
X4C_PRODUCTION_FOLD_CODEWORD_BYTES = 17_179_869_056
X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES = 34_359_737_248
X4C_X4B_OPEN_WALL_S = 6.683_486_611
X4C_NO_TEARDOWN_OPEN_ANCHOR_S = 0.109_631_491
X4C_POD_PROFILE = "runpod-a100-x4c-v1"
X4C_LEGACY_CAUSAL_MILESTONE = "X4c-phase2-legacy-causal-diagnostic"
X4C_LIFECYCLE_PROBE_MILESTONE = "X4c-phase2-exact-size-lifecycle-probe"
X4C_ONBOARDING_MILESTONE = "X4c-v1-A100-onboarding"
X4C_ONLINE_MILESTONE = "X4c-v1-A100-online"
X4C_GPT2_ONBOARDING_MILESTONE = "X4c-GPT2-real-weight-onboarding"
X4C_GPT2_ONLINE_MILESTONE = "X4c-GPT2-real-weight-online"
X4C_GPT2_ACCELERATED_ONLINE_MILESTONE = (
    "X4c-GPT2-real-weight-online-accelerated"
)
X4C_GPT2_V3_ONBOARDING_MILESTONE = (
    "X4c-GPT2-real-weight-onboarding-crypto-id-v1"
)
X4C_GPT2_V3_ONLINE_MILESTONE = "X4c-GPT2-real-weight-online-crypto-id-v1"
X4C_GPT2_V3_ACCELERATED_ONLINE_MILESTONE = (
    "X4c-GPT2-real-weight-online-accelerated-crypto-id-v1"
)
X4C_CRYPTO_BUILD_ID_SCHEME = "volta-x4c-crypto-build-v1"
X4C_SCHEMA3_VALIDATOR_RULESET = "volta-x4c-schema3-validator-v1"
X4C_SCHEMA3_VALIDATION_RECEIPT_MILESTONE = (
    "X4c-GPT2-schema3-validation-receipt"
)
X4C_SCHEMA3_REBUILD_ADMISSION_MILESTONE = (
    "X4c-GPT2-schema3-rebuild-admission"
)
X4C_CAMPAIGN_TARGET_S = 2_700
X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES = 1_364_224
X4C_PRODUCTION_FRESH_DEVICE_GENERATED_BYTES = 35_727_436_640
X4C_PRODUCTION_REUSED_DEVICE_GENERATED_BYTES = 35_727_436_512
X4C_GPT2_REBUILD_PREFLIGHT_MILESTONE = "X4c-GPT2-rebuild-preflight"
X4C_GPT2_PROTOCOL = "x4-zkdeepfold-ud-e29-v4"
X4C_GPT2_SELECTED_TAPE = (
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299"
)
X4C_GPT2_INPUT_SHA256 = {
    "input_bin_sha256": "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a",
    "input_json_sha256": "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c",
    "input_params_sha256": "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac",
    "golden_p5_sha256": "4ac774f208a414bf7fb591a29bd455968ce2d89846255fe8239eabd9b5c92f45",
    "golden_p6_sha256": "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862",
    "model_safetensors_sha256": "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707",
}
X4C_V1_DESIGN_SHA256 = (
    "9a3c64a65902046ba0a2b1891ff8fce03690d870773a346f7128b9f75f7a1164"
)
X4C_DURABLE_COEFFICIENT_BYTES = 9_618_587_648
X4C_DURABLE_ROOT_BYTES = 160
X4C_DURABLE_BYTES = X4C_DURABLE_COEFFICIENT_BYTES + X4C_DURABLE_ROOT_BYTES
X4C_INITIAL_ORACLE_BYTES = 76_948_701_184
X4C_INITIAL_OUTER_CACHE_BYTES = 37_094_424_416
X4C_ARENA_BYTES = 43_486_546_048
X4C_PACKED_OPENING_BYTES = 2_615_414
X4C_GLOBAL_FOLDING_PROOF_BYTES = 2_617_860
X4C_MANDATORY_NON_QUERY_BYTES = 67_822
X4C_COHORTS = (
    (0xA5000001, 4_294_967_296, 34_359_738_336),
    (0xA5000002, 4_831_838_208, 2_147_483_616),
    (0xA5000003, 436_207_616, 536_870_880),
    (0xA5000100, 4_194_304, 33_554_400),
    (0xA5000101, 51_380_224, 16_777_184),
)
X4C_PRODUCTION_SEALED_STATE_BYTES = (
    X4C_PRODUCTION_FOLD_CODEWORD_BYTES + X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
)
X4C_MIN_HOST_RAM_BYTES = 256 * 1024**3
X4C_MIN_LOCAL_STORAGE_BYTES = 150_000_000_000
X4C_LEGACY_SEAL_PHASES = {
    "coefficient_clone_allocation",
    "e_ntt",
    "coefficient_oracle_write",
    "flush_sync_data",
    "oracle_reread_n4_inner",
    "n4_outer_levels",
    "full_oracle_comparison",
    "cpu_codeword_cache_clone_back",
    "file_cleanup",
    "directory_cleanup",
    "backend_finish_synchronization_boundary",
}
X4C_LEGACY_OPENING_PHASES = {
    "draw_validation_schedule",
    "initial_group_opening",
    "fold_round_opening",
    "inner_hashing_path_assembly",
    "schedule_digest_structural_validation",
    "canonical_encode_serialization",
    "destroy_codewords",
    "destroy_outer_cache_levels",
    "destroy_remaining_sealed_state",
}

LAYER_PARAMS = {
    "rows": 1 << 10,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}
EMBED_PARAMS = {
    "rows": 1 << 13,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}


def git(args: list[str], default: str = "") -> str:
    try:
        out = subprocess.check_output(["git", *args], cwd=REPO, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return default
    return out.decode().strip()


def git_dirty() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return True
    return bool(out)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    data["_path"] = str(path.relative_to(REPO))
    data["_mtime"] = path.stat().st_mtime
    return data


def load_results(results_dir: Path) -> list[dict[str, Any]]:
    return [load_json(p) for p in sorted(results_dir.glob("*.json"))]


def _x4_v4_cpu_result_valid(row: dict[str, Any]) -> bool:
    gate = row.get("gate")
    abba = row.get("abba")
    recompute = row.get("recompute_case")
    touched = row.get("touched_family")
    return (
        row.get("schema") == 2
        and row.get("milestone") == "X4-v4-CPU-synthetic"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("design_sha256") == X4_V4_DESIGN_SHA256
        and row.get("query_count") == 111
        and row.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and row.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and row.get("required_soundness_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and row.get("soundness_resummed_new_terms") == 0
        and row.get("security_counter_inventory") == X4_V4_COUNTER_FAMILIES
        and isinstance(touched, list)
        and [case.get("touched_blocks") for case in touched] == [1, 2, 4, 8, 16]
        and all(case.get("accepted") is True for case in touched)
        and all(
            case.get("bytes", {}).get("closed_formula_total")
            == case.get("bytes", {}).get("serialized_total")
            for case in touched
        )
        and isinstance(recompute, dict)
        and recompute.get("policy") == "RecomputeOracleAndMerkle"
        and recompute.get("traffic", {}).get("recomputed_source_bytes_read", 0) > 0
        and recompute.get("traffic", {}).get("recomputed_oracle_bytes", 0) > 0
        and recompute.get("traffic", {}).get("recomputed_merkle_bytes", 0) > 0
        and row.get("recompute_matches_persisted_response") is True
        and isinstance(abba, dict)
        and abba.get("order") == "A/B/B/A"
        and abba.get("ceiling") == 1.05
        and abba.get("pass") is True
        and isinstance(gate, dict)
        and gate.get("g5_verdict") == "PASS"
        and gate.get("g6_verdict") == "PASS"
        and gate.get("overall_x4_verdict")
        == "NOT_EVALUATED_UNTIL_GPT2_MIGRATION_AND_A100_RECORDS"
    )


def validate_x4_v4_cpu_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_cpu_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4_v4_migration_result_valid(row: dict[str, Any]) -> bool:
    codec = row.get("codec")
    golden = row.get("golden_decode")
    historical = row.get("historical_records")
    gate = row.get("gate")
    return (
        row.get("schema") == 1
        and row.get("milestone") == "X4-v4-GPT2-migration"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("design_sha256") == X4_V4_DESIGN_SHA256
        and row.get("query_count") == 111
        and row.get("rate") == "1/8"
        and row.get("maximum_claim_union") == 3_320
        and row.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and row.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and row.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and row.get("soundness_resummed_new_terms") == 0
        and isinstance(codec, dict)
        and codec.get("opened_symbols") == 27_564
        and codec.get("all_real_sibling_digests") == 67_930
        and codec.get("packed_opening_frame") == X4_V4_PACKED_OPENING_BYTES
        and codec.get("summed_bytes") == X4_V4_PCS_BYTES
        and codec.get("serialized_bytes") == X4_V4_PCS_BYTES
        and isinstance(codec.get("encoded_sha256"), str)
        and len(codec["encoded_sha256"]) == 64
        and row.get("complete_pcs_bytes") == X4_V4_PCS_BYTES
        and row.get("g3_limit_bytes") == 4_000_000
        and row.get("g3_headroom_bytes") == 1_316_764
        and row.get("non_pcs_response_bytes") == 41_270_464
        and row.get("measured_response_bytes") == X4_V4_RESPONSE_BYTES
        and row.get("response_limit_bytes") == 45_270_464
        and row.get("response_headroom_bytes") == 1_316_764
        and row.get("correlations_gpt2_claim_reduction") == 2_208
        and row.get("correlations_gpt2_seam") == 106
        and row.get("correlations_gpt2_total") == 2_314
        and row.get("logical_first_oracle_floor_bytes") == 31_923_699_712
        and row.get("production_codec") is True
        and row.get("cryptographic_oracle_materialized") is False
        and isinstance(golden, dict)
        and golden.get("prompt_tokens") == 100
        and golden.get("decode_tokens") == 50
        and golden.get("checked") is True
        and golden.get("exact_match") is True
        and isinstance(historical, list)
        and len(historical) == 3
        and all(pin.get("unchanged") is True for pin in historical)
        and row.get("historical_rows_mutated") is False
        and isinstance(gate, dict)
        and gate.get("g3_communication", "").startswith("PASS")
        and gate.get("overall_x4") == "NOT EVALUATED UNTIL A100 RECORDS"
    )


def validate_x4_v4_migration_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_migration_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4d_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _x4d_exact_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _x4d_codec_reference_valid(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    amendment = (
        _x4d_exact_int(row.get("schema"), 2)
        and row.get("milestone") == X4D_CODEC_AMENDMENT_MILESTONE
    )
    historical = (
        _x4d_exact_int(row.get("schema"), 1)
        and row.get("milestone") == X4D_CODEC_REFERENCE_MILESTONE
    )
    if not amendment and not historical:
        return False
    top_level_keys = {
        "schema",
        "milestone",
        "profile",
        "git_sha",
        "git_dirty",
        "design_path",
        "design_sha256",
        "source_path",
        "source_sha256",
        "preflight_path",
        "preflight_sha256",
        "historical_references_modified",
        "proof_or_gate_verdict",
        "response",
        "settlements",
    }
    if amendment:
        top_level_keys.add("fresh_query_length_semantics")
    if set(row) != top_level_keys:
        return False
    source_git_sha = (
        X4D_CODEC_AMENDMENT_SOURCE_GIT_SHA
        if amendment
        else X4D_CODEC_SOURCE_GIT_SHA
    )
    design_sha256 = (
        X4D_CODEC_AMENDMENT_DESIGN_SHA256 if amendment else X4D_DESIGN_SHA256
    )
    generator_sha256 = (
        X4D_CODEC_AMENDMENT_GENERATOR_SHA256
        if amendment
        else X4D_CODEC_GENERATOR_SHA256
    )
    references = (
        X4D_CODEC_AMENDMENT_REFERENCES
        if amendment
        else X4D_SETTLEMENT_REFERENCES
    )
    response = row["response"]
    settlements = row["settlements"]
    if not (
        row["profile"] == X4D_PROFILE
        and row["git_sha"] == source_git_sha
        and _x4d_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["design_path"] == "docs/x4d-deferred-settlement-design.md"
        and row["design_sha256"] == design_sha256
        and row["source_path"]
        == "rust/volta-bench/src/bin/x4d_codec_reference.rs"
        and row["source_sha256"] == generator_sha256
        and row["preflight_path"]
        == "benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json"
        and row["preflight_sha256"] == X4D_FROZEN_PREFLIGHT_SHA256
        and row["historical_references_modified"] is False
        and row["proof_or_gate_verdict"] is False
        and (
            not amendment
            or row["fresh_query_length_semantics"]
            == X4D_CODEC_AMENDMENT_SEMANTICS
        )
        and isinstance(response, dict)
        and set(response)
        == {
            "accounting_kind",
            "product_state_at_delivery",
            "model_transcript_bytes",
            "model_mac_closure_bytes",
            "pcs_bytes",
            "exact_response_bytes",
            "materialized_wire_fixture",
        }
        and response["accounting_kind"]
        == "exact_x4c_response_traffic_projection_without_pcs"
        and response["product_state_at_delivery"] == "WEIGHT_PENDING"
        and _x4d_exact_int(response["model_transcript_bytes"], 41_270_400)
        and _x4d_exact_int(response["model_mac_closure_bytes"], 64)
        and _x4d_exact_int(response["pcs_bytes"], 0)
        and _x4d_exact_int(response["exact_response_bytes"], X4D_RESPONSE_BYTES)
        and response["materialized_wire_fixture"] is False
        and isinstance(settlements, list)
        and len(settlements) == len(references)
    ):
        return False
    settlement_keys = {
        "responses",
        "claims",
        "masked_groups",
        "active_chain_polynomials",
        "fold_rounds",
        "query_draws",
        "serialized_bytes",
        "expected_bytes",
        "sha256",
        "settlement_bytes_per_response",
        "total_amortized_bytes_per_response",
    }
    if amendment:
        settlement_keys |= {
            "packed_opening_bytes",
            "max_packed_opening_bytes",
            "fixed_size_padding_bytes",
        }
    for actual, (responses, encoded_bytes, digest) in zip(
        settlements, references, strict=True
    ):
        if not (
            isinstance(actual, dict)
            and set(actual) == settlement_keys
            and _x4d_exact_int(actual["responses"], responses)
            and _x4d_exact_int(actual["claims"], 102 * responses)
            and _x4d_exact_int(actual["masked_groups"], 51 * responses)
            and _x4d_exact_int(actual["active_chain_polynomials"], 102)
            and _x4d_exact_int(actual["fold_rounds"], 27)
            and _x4d_exact_int(actual["query_draws"], 111)
            and (
                not amendment
                or (
                    _x4d_exact_int(actual["packed_opening_bytes"], 2_615_414)
                    and _x4d_exact_int(
                        actual["max_packed_opening_bytes"], 2_740_598
                    )
                    and _x4d_exact_int(
                        actual["fixed_size_padding_bytes"], 125_184
                    )
                )
            )
            and _x4d_exact_int(actual["serialized_bytes"], encoded_bytes)
            and _x4d_exact_int(actual["expected_bytes"], encoded_bytes)
            and actual["sha256"] == digest
            and _x4d_hex(actual["sha256"], 64)
            and type(actual["settlement_bytes_per_response"]) is float
            and actual["settlement_bytes_per_response"] == encoded_bytes / responses
            and type(actual["total_amortized_bytes_per_response"]) is float
            and actual["total_amortized_bytes_per_response"]
            == X4D_RESPONSE_BYTES + encoded_bytes / responses
        ):
            return False
    return True


def validate_x4d_codec_reference(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4d_codec_reference_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4d_number(value: Any, *, positive: bool = False) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and (value > 0 if positive else value >= 0)
    )


def _x4d_phase3_hardware_valid(row: Any) -> bool:
    keys = {
        "gpu_name",
        "gpu_uuid",
        "gpu_memory_mib",
        "selected_gpu_count",
        "mem_total_bytes",
        "volume_total_bytes",
        "volume_available_bytes",
        "response_cpu_ids",
        "settlement_cpu_ids",
        "split_policy_valid",
        "gpu_pass",
        "ram_pass",
        "volume_pass",
        "overall_pass",
    }
    if not isinstance(row, dict) or set(row) != keys:
        return False
    response = row["response_cpu_ids"]
    settlement = row["settlement_cpu_ids"]
    gpu_pass = (
        "A100-SXM4-80GB" in row["gpu_name"]
        and _x4d_hex(row["gpu_uuid"].removeprefix("GPU-").replace("-", ""), 32)
        and type(row["gpu_memory_mib"]) is int
        and row["gpu_memory_mib"] >= 81_920
        and _x4d_exact_int(row["selected_gpu_count"], 1)
    )
    ram_pass = (
        type(row["mem_total_bytes"]) is int
        and row["mem_total_bytes"] >= 274_877_906_944
    )
    volume_pass = (
        type(row["volume_total_bytes"]) is int
        and row["volume_total_bytes"] >= 150_000_000_000
        and type(row["volume_available_bytes"]) is int
        and 0 <= row["volume_available_bytes"] <= row["volume_total_bytes"]
    )
    split = (
        isinstance(response, list)
        and isinstance(settlement, list)
        and len(response) == 8
        and len(settlement) == 27
        and all(type(cpu) is int and cpu >= 0 for cpu in [*response, *settlement])
        and len(set(response)) == 8
        and len(set(settlement)) == 27
        and set(response).isdisjoint(settlement)
    )
    return (
        row["split_policy_valid"] is split
        and row["gpu_pass"] is gpu_pass
        and row["ram_pass"] is ram_pass
        and row["volume_pass"] is volume_pass
        and row["overall_pass"] is (gpu_pass and ram_pass and volume_pass and split)
    )


def _x4d_phase3_preflight_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and set(row)
        == {
            "schema",
            "milestone",
            "git_sha",
            "git_dirty",
            "profile",
            "protocol",
            "design_sha256",
            "producer_source_sha256",
            "hardware",
            "inputs_exact",
            "soundness_expression",
            "soundness_bits",
            "overall_pass",
        }
        and _x4d_exact_int(row["schema"], 1)
        and row["milestone"] == X4D_PHASE3_PREFLIGHT_MILESTONE
        and _x4d_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["profile"] == X4D_PHASE3_PROFILE
        and row["protocol"] == X4D_PHASE3_PROTOCOL
        and row["design_sha256"] == X4D_PHASE3_DESIGN_SHA256
        and row["producer_source_sha256"] == X4D_PHASE3_PRODUCER_SHA256
        and _x4d_phase3_hardware_valid(row["hardware"])
        and row["hardware"]["overall_pass"] is True
        and row["inputs_exact"] is True
        and row["soundness_expression"] == X4D_SOUNDNESS_EXPRESSION
        and row["soundness_bits"] == X4D_SOUNDNESS_BITS
        and row["overall_pass"] is True
    )


def validate_x4d_phase3_preflight(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4d_phase3_preflight_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4d_upper_median(values: list[float]) -> float:
    return sorted(values)[len(values) // 2]


def _x4d_phase3_response_valid(row: Any, ordinal: int, role: str) -> bool:
    keys = {
        "ordinal",
        "role",
        "response_nonce_digest",
        "model_prove_s",
        "model_verify_s",
        "claim_freeze_s",
        "total_g1_s",
        "prefill_prove_upper_s",
        "max_decode_marginal_s",
        "flatness_last_over_first",
        "h2d_bytes",
        "synchronization_wall_upper_s",
        "model_transcript_bytes",
        "model_mac_closure_bytes",
        "response_bytes",
        "pcs_bytes",
        "product_state_at_delivery",
        "transcript_replay_bytes",
        "transcript_replay_labels",
        "correlations_consumed",
        "freeze_journal",
        "connection_audit",
        "accepted",
    }
    if not isinstance(row, dict) or set(row) != keys:
        return False
    freeze = row["freeze_journal"]
    audit = row["connection_audit"]
    expected_raw = 4_793_590 + 2 * (181_933 + 2)
    return (
        _x4d_exact_int(row["ordinal"], ordinal)
        and row["role"] == role
        and _x4d_hex(row["response_nonce_digest"], 64)
        and all(
            _x4d_number(row[key], positive=True)
            for key in ("model_prove_s", "model_verify_s", "claim_freeze_s", "total_g1_s")
        )
        and math.isclose(
            row["total_g1_s"],
            row["model_prove_s"] + row["model_verify_s"] + row["claim_freeze_s"],
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
        and _x4d_number(row["prefill_prove_upper_s"])
        and _x4d_number(row["max_decode_marginal_s"], positive=True)
        and _x4d_number(row["flatness_last_over_first"], positive=True)
        and type(row["h2d_bytes"]) is int
        and row["h2d_bytes"] >= 0
        and _x4d_number(row["synchronization_wall_upper_s"])
        and _x4d_exact_int(row["model_transcript_bytes"], 41_270_400)
        and _x4d_exact_int(row["model_mac_closure_bytes"], 64)
        and _x4d_exact_int(row["response_bytes"], 41_270_464)
        and _x4d_exact_int(row["pcs_bytes"], 0)
        and row["product_state_at_delivery"] == "WEIGHT_PENDING"
        and _x4d_exact_int(row["transcript_replay_bytes"], 41_034_112)
        and _x4d_exact_int(row["transcript_replay_labels"], 25)
        and _x4d_exact_int(row["correlations_consumed"], expected_raw)
        and isinstance(freeze, dict)
        and set(freeze)
        == {
            "response_nonce_digest",
            "first_claim_index",
            "claim_count",
            "ending_accumulator_digest",
        }
        and _x4d_hex(freeze["response_nonce_digest"], 64)
        and _x4d_exact_int(freeze["first_claim_index"], 102 * ordinal)
        and _x4d_exact_int(freeze["claim_count"], 102)
        and _x4d_hex(freeze["ending_accumulator_digest"], 64)
        and isinstance(audit, dict)
        and set(audit)
        == {
            "response_nonce_digest",
            "allocation_digest",
            "channel_ledger_digest",
            "correlations_consumed",
            "channel_frames",
        }
        and audit["response_nonce_digest"] == freeze["response_nonce_digest"]
        and _x4d_hex(audit["allocation_digest"], 64)
        and _x4d_hex(audit["channel_ledger_digest"], 64)
        and _x4d_exact_int(audit["correlations_consumed"], expected_raw)
        and type(audit["channel_frames"]) is int
        and audit["channel_frames"] >= 0
        and row["accepted"] is True
    )


def _x4d_phase3_g1_valid(row: Any, responses: list[dict[str, Any]]) -> bool:
    keys = {
        "selected_total_s",
        "selected_claim_freeze_s",
        "selected_prefill_upper_s",
        "selected_decode_marginal_s",
        "selected_h2d_bytes",
        "selected_sync_wall_upper_s",
        "selected_flatness",
        "total_pass",
        "freeze_pass",
        "prefill_pass",
        "decode_pass",
        "h2d_pass",
        "sync_pass",
        "flatness_pass",
        "overall_pass",
    }
    if not isinstance(row, dict) or set(row) != keys:
        return False
    measured = responses[1:4]
    expected = {
        "selected_total_s": _x4d_upper_median([item["total_g1_s"] for item in measured]),
        "selected_claim_freeze_s": _x4d_upper_median(
            [item["claim_freeze_s"] for item in measured]
        ),
        "selected_prefill_upper_s": _x4d_upper_median(
            [item["prefill_prove_upper_s"] for item in measured]
        ),
        "selected_decode_marginal_s": _x4d_upper_median(
            [item["max_decode_marginal_s"] for item in measured]
        ),
        "selected_h2d_bytes": max(item["h2d_bytes"] for item in measured),
        "selected_sync_wall_upper_s": max(
            item["synchronization_wall_upper_s"] for item in measured
        ),
        "selected_flatness": max(item["flatness_last_over_first"] for item in measured),
    }
    if any(row[key] != value for key, value in expected.items()):
        return False
    passes = {
        "total_pass": row["selected_total_s"] <= 5.0,
        "freeze_pass": row["selected_claim_freeze_s"] <= 0.025,
        "prefill_pass": row["selected_prefill_upper_s"] <= 10.0,
        "decode_pass": row["selected_decode_marginal_s"] <= 4.0,
        "h2d_pass": row["selected_h2d_bytes"] <= 100_000_000,
        "sync_pass": row["selected_sync_wall_upper_s"] <= 0.150,
        "flatness_pass": row["selected_flatness"] <= 1.5,
    }
    return all(row[key] is value for key, value in passes.items()) and row[
        "overall_pass"
    ] is all(passes.values())


def _x4d_phase3_settlement_valid(
    row: Any, responses: list[dict[str, Any]]
) -> bool:
    required = {
        "responses",
        "frozen_claims",
        "masked_groups",
        "settlement_epoch",
        "settlement_bytes",
        "expected_settlement_bytes",
        "amortized_settlement_bytes_per_response",
        "historical_four_mb_scope",
        "seal_to_terminal_wall_s",
        "proof_driver_wall_s",
        "auxiliary_materialization_wall_s",
        "response_priority_pause_wall_s",
        "active_cpu_host_window_s",
        "active_gpu_lease_host_window_s",
        "lease_wait_wall_s",
        "open_wall_s",
        "verify_wall_s",
        "open_pass",
        "verify_pass",
        "every_covered_response_weight_verified",
        "exact_bytes",
        "exact_correlations",
        "fresh_auxiliary_masks",
        "static_weight_roots_reused",
        "query_draws",
        "soundness_expression",
        "soundness_bits",
        "interference",
        "accepted",
    }
    if not isinstance(row, dict) or set(row) != required:
        return False
    interference = row["interference"]
    if not isinstance(interference, dict) or set(interference) != {
        "order",
        "isolated_response_s",
        "settlement_queued_response_s",
        "isolated_upper_median_s",
        "settlement_queued_upper_median_s",
        "absolute_delta_s",
        "percentage_delta",
        "settlement_cpu_overlap_intervals",
        "settlement_gpu_overlap_intervals",
        "accounting_semantics",
    }:
        return False
    isolated = [responses[14]["total_g1_s"], responses[18]["total_g1_s"]]
    queued = [responses[16]["total_g1_s"], responses[17]["total_g1_s"]]
    isolated_upper = _x4d_upper_median(isolated)
    queued_upper = _x4d_upper_median(queued)
    isolated_upper_ns = int(isolated_upper * 1e9)
    queued_upper_ns = int(queued_upper * 1e9)
    delta = (queued_upper_ns - isolated_upper_ns) / 1e9
    percentage = 100.0 * (queued_upper_ns - isolated_upper_ns) / isolated_upper_ns
    open_pass = row["open_wall_s"] <= 1.50
    verify_pass = row["verify_wall_s"] <= 0.25
    accepted = (
        row["every_covered_response_weight_verified"]
        and row["exact_bytes"]
        and row["exact_correlations"]
        and open_pass
        and verify_pass
    )
    return (
        _x4d_exact_int(row["responses"], 16)
        and _x4d_exact_int(row["frozen_claims"], 1_632)
        and _x4d_exact_int(row["masked_groups"], 816)
        and _x4d_exact_int(row["settlement_epoch"], 1)
        and _x4d_exact_int(row["settlement_bytes"], X4D_PHASE3_SETTLEMENT_BYTES)
        and _x4d_exact_int(row["expected_settlement_bytes"], X4D_PHASE3_SETTLEMENT_BYTES)
        and row["amortized_settlement_bytes_per_response"]
        == X4D_PHASE3_SETTLEMENT_BYTES / 16
        and row["historical_four_mb_scope"]
        == "4,000,000 B is the immutable X4/X4b/X4c per-response PCS ceiling; X4d settlement uses the pinned batch formula"
        and all(
            _x4d_number(row[key], positive=True)
            for key in (
                "seal_to_terminal_wall_s",
                "proof_driver_wall_s",
                "auxiliary_materialization_wall_s",
                "response_priority_pause_wall_s",
                "active_cpu_host_window_s",
                "active_gpu_lease_host_window_s",
                "open_wall_s",
                "verify_wall_s",
            )
        )
        and _x4d_number(row["lease_wait_wall_s"])
        and math.isclose(
            row["active_cpu_host_window_s"],
            row["auxiliary_materialization_wall_s"] + row["proof_driver_wall_s"],
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
        and row["active_gpu_lease_host_window_s"] == row["proof_driver_wall_s"]
        and row["open_pass"] is open_pass
        and row["verify_pass"] is verify_pass
        and row["every_covered_response_weight_verified"] is True
        and row["exact_bytes"] is True
        and row["exact_correlations"] is True
        and _x4d_exact_int(row["fresh_auxiliary_masks"], 51)
        and _x4d_exact_int(row["static_weight_roots_reused"], 3)
        and _x4d_exact_int(row["query_draws"], 111)
        and row["soundness_expression"] == X4D_SOUNDNESS_EXPRESSION
        and row["soundness_bits"] == X4D_SOUNDNESS_BITS
        and interference["order"] == "A1,B1,B2,A2"
        and interference["isolated_response_s"] == isolated
        and interference["settlement_queued_response_s"] == queued
        and interference["isolated_upper_median_s"] == isolated_upper
        and interference["settlement_queued_upper_median_s"] == queued_upper
        and math.isclose(
            interference["absolute_delta_s"], delta, rel_tol=1e-9, abs_tol=1e-9
        )
        and math.isclose(
            interference["percentage_delta"], percentage, rel_tol=1e-9, abs_tol=1e-9
        )
        and _x4d_exact_int(interference["settlement_cpu_overlap_intervals"], 0)
        and _x4d_exact_int(interference["settlement_gpu_overlap_intervals"], 0)
        and interference["accounting_semantics"]
        == "B responses execute under strict response priority while the sealed settlement is queued; no CPU/GPU interval is falsely reported concurrent"
        and row["accepted"] is accepted
    )


def _x4d_phase3_online_valid(row: Any, onboarding: Any, onboarding_sha: str) -> bool:
    keys = {
        "schema",
        "milestone",
        "git_sha",
        "git_dirty",
        "producer_source_sha256",
        "profile",
        "protocol",
        "design_sha256",
        "cloud",
        "hardware",
        "onboarding_path",
        "onboarding_sha256",
        "onboarding_exact",
        "crypto_build_id_scheme",
        "crypto_build_id",
        "durable_tier_bytes",
        "rebuild_wall_s",
        "rebuild_rows",
        "rebuild_roots",
        "rebuild_roots_equal_onboarding",
        "old_auxiliary_roots_rejected_for_settlement",
        "setup_wall_s",
        "responses",
        "g1",
        "settlement",
        "cap_test_name",
        "cap_3321_permanent_test_present",
        "cap_preflight_3321_rejected",
        "soundness_expression_byte_exact",
        "g2_permanent_tests",
        "g6_test_name",
        "g6_abort_before_settlement_terminal_unverified",
        "no_retry_same_connection",
        "provider_contract_state_at_delivery",
        "provider_contract_state_at_settlement",
        "historical_rows_modified",
        "overall_pass",
    }
    if not isinstance(row, dict) or set(row) != keys:
        return False
    cloud = row["cloud"]
    responses = row["responses"]
    roles = [
        "g1-warmup",
        "g1-measured",
        "g1-measured",
        "g1-measured",
        *["connection-fill"] * 10,
        "abba-isolated-a1",
        "connection-fill",
        "abba-settlement-queued-b",
        "abba-settlement-queued-b",
        "abba-isolated-a2",
    ]
    if len(roles) != X4D_PHASE3_CONNECTION_RESPONSES:
        return False
    structural = (
        _x4d_exact_int(row["schema"], 1)
        and row["milestone"] == X4D_PHASE3_ONLINE_MILESTONE
        and _x4d_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["producer_source_sha256"] == X4D_PHASE3_PRODUCER_SHA256
        and row["profile"] == X4D_PHASE3_PROFILE
        and row["protocol"] == X4D_PHASE3_PROTOCOL
        and row["design_sha256"] == X4D_PHASE3_DESIGN_SHA256
        and isinstance(cloud, dict)
        and set(cloud)
        == {
            "provider",
            "instance_id",
            "region",
            "image",
            "driver_version",
            "cuda_version",
            "gpu_sku",
            "cpu_model",
            "ram_gib",
            "vcpus",
        }
        and cloud["provider"].lower() == "runpod"
        and "A100-SXM4-80GB" in cloud["gpu_sku"]
        and all(isinstance(value, str) and value for value in cloud.values())
        and _x4d_phase3_hardware_valid(row["hardware"])
        and row["hardware"]["overall_pass"] is True
        and row["onboarding_sha256"] == onboarding_sha
        and _x4d_hex(row["onboarding_sha256"], 64)
        and row["onboarding_exact"] is True
        and isinstance(onboarding, dict)
        and onboarding.get("schema") == 3
        and onboarding.get("milestone")
        == "X4c-GPT2-real-weight-onboarding-crypto-id-v1"
        and onboarding.get("git_dirty") is False
        and onboarding.get("overall_pass") is True
        and row["crypto_build_id_scheme"] == onboarding.get("crypto_build_id_scheme")
        and row["crypto_build_id"] == onboarding.get("crypto_build_id")
        and _x4d_hex(row["crypto_build_id"], 64)
        and _x4d_exact_int(row["durable_tier_bytes"], 9_618_587_808)
        and _x4d_number(row["rebuild_wall_s"], positive=True)
        and isinstance(row["rebuild_rows"], list)
        and len(row["rebuild_rows"]) == 5
        and all(
            isinstance(item, dict)
            and item.get("accepted") is True
            and type(item.get("cohort_id")) is int
            for item in row["rebuild_rows"]
        )
        and isinstance(row["rebuild_roots"], list)
        and len(row["rebuild_roots"]) == 5
        and all(_x4d_hex(root, 64) for root in row["rebuild_roots"])
        and row["rebuild_roots"] == onboarding.get("warmup_root_set")
        and row["rebuild_roots_equal_onboarding"] is True
        and row["old_auxiliary_roots_rejected_for_settlement"] is True
        and _x4d_number(row["setup_wall_s"], positive=True)
        and isinstance(responses, list)
        and len(responses) == X4D_PHASE3_CONNECTION_RESPONSES
        and all(
            _x4d_phase3_response_valid(response, ordinal, roles[ordinal])
            for ordinal, response in enumerate(responses)
        )
        and _x4d_phase3_g1_valid(row["g1"], responses)
        and _x4d_phase3_settlement_valid(row["settlement"], responses)
        and row["cap_test_name"] == "claim_3321_refuses_until_settlement_succeeds"
        and row["cap_3321_permanent_test_present"] is True
        and row["cap_preflight_3321_rejected"] is True
        and row["soundness_expression_byte_exact"] is True
        and row["g2_permanent_tests"] == X4D_PHASE3_G2_TESTS
        and row["g6_test_name"]
        == "explicit_abort_before_settlement_marks_pending_terminal_unverified"
        and row["g6_abort_before_settlement_terminal_unverified"] is True
        and row["no_retry_same_connection"] is True
        and row["provider_contract_state_at_delivery"]
        == "complete and fully authenticated; weight consistency WEIGHT_PENDING"
        and row["provider_contract_state_at_settlement"]
        == "covered response set pronounced WEIGHT_VERIFIED only after settlement acceptance"
        and row["historical_rows_modified"] is False
    )
    expected_overall = (
        structural
        and row["g1"]["overall_pass"]
        and row["settlement"]["accepted"]
        and row["g6_abort_before_settlement_terminal_unverified"]
        and row["no_retry_same_connection"]
    )
    return structural and row["overall_pass"] is expected_overall


def validate_x4d_phase3_online(path: Path, onboarding_path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        if not onboarding_path.is_absolute():
            onboarding_path = REPO / onboarding_path
        onboarding_bytes = onboarding_path.read_bytes()
        onboarding_sha = hashlib.sha256(onboarding_bytes).hexdigest()
        onboarding = json.loads(onboarding_bytes)
        with path.open("r", encoding="utf-8") as handle:
            return _x4d_phase3_online_valid(
                json.load(handle), onboarding, onboarding_sha
            )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4d1_run_summary_valid(row: Any, responses: int) -> bool:
    keys = {
        "input_path",
        "input_sha256",
        "responses",
        "settlement_wall_s",
        "selected_g1_wall_s",
        "g1_overall_pass",
        "settlement_accepted",
        "min_response_wall_s",
        "max_response_wall_s",
        "response_bytes",
        "interference_percentage_delta",
        "initial_encoded_symbols_read",
        "combined_codeword_symbols",
        "materialized_relation_terms",
        "fused_relation_terms",
    }
    return (
        isinstance(row, dict)
        and set(row) == keys
        and isinstance(row["input_path"], str)
        and Path(row["input_path"]).name.startswith("x4d1-")
        and Path(row["input_path"]).suffix == ".json"
        and _x4d_hex(row["input_sha256"], 64)
        and _x4d_exact_int(row["responses"], responses)
        and all(
            _x4d_number(row[key], positive=True)
            for key in (
                "settlement_wall_s",
                "selected_g1_wall_s",
                "min_response_wall_s",
                "max_response_wall_s",
            )
        )
        and row["min_response_wall_s"] <= row["max_response_wall_s"]
        and isinstance(row["g1_overall_pass"], bool)
        and isinstance(row["settlement_accepted"], bool)
        and _x4d_exact_int(row["response_bytes"], X4D1_RESPONSE_BYTES)
        and isinstance(row["interference_percentage_delta"], (int, float))
        and not isinstance(row["interference_percentage_delta"], bool)
        and math.isfinite(row["interference_percentage_delta"])
        and _x4d_exact_int(
            row["initial_encoded_symbols_read"], X4D1_INITIAL_ENCODED_SYMBOLS
        )
        and _x4d_exact_int(
            row["combined_codeword_symbols"], X4D1_COMBINED_CODEWORD_SYMBOLS
        )
        and _x4d_exact_int(row["materialized_relation_terms"], 102)
        and _x4d_exact_int(row["fused_relation_terms"], 102 * (responses - 1))
    )


def _x4d1_flatness_valid(row: Any) -> bool:
    keys = {
        "schema",
        "milestone",
        "git_sha",
        "git_dirty",
        "producer_source_sha256",
        "profile",
        "protocol",
        "design_sha256",
        "same_host",
        "wall_semantics",
        "k1",
        "k16",
        "settlement_wall_ratio_k16_over_k1",
        "flatness_ceiling",
        "wall_flatness_pass",
        "initial_encoded_symbols_equal",
        "combined_codeword_symbols_equal",
        "physical_counter_gate_pass",
        "g1_rerun_pass",
        "response_bytes_unchanged",
        "interference_ceiling_percentage_delta",
        "interference_rerun_pass",
        "inherited_settlement_gates_pass",
        "binding_gate_verdict_verbatim",
        "informative_target",
        "historical_rows_modified",
        "overall_pass",
    }
    if not isinstance(row, dict) or set(row) != keys:
        return False
    k1 = row["k1"]
    k16 = row["k16"]
    informative = row["informative_target"]
    if (
        not _x4d1_run_summary_valid(k1, 1)
        or not _x4d1_run_summary_valid(k16, 16)
        or not isinstance(informative, dict)
        or set(informative)
        != {
            "lower_s",
            "upper_s",
            "k16_at_or_below_upper",
            "affects_binding_gate",
            "policy",
        }
    ):
        return False
    ratio = k16["settlement_wall_s"] / k1["settlement_wall_s"]
    wall_pass = ratio <= X4D1_FLATNESS_CEILING
    initial_equal = (
        k1["initial_encoded_symbols_read"] == k16["initial_encoded_symbols_read"]
    )
    combined_equal = (
        k1["combined_codeword_symbols"] == k16["combined_codeword_symbols"]
    )
    counter_pass = initial_equal and combined_equal
    g1_pass = k1["g1_overall_pass"] and k16["g1_overall_pass"]
    inherited_pass = k1["settlement_accepted"] and k16["settlement_accepted"]
    interference_pass = (
        k16["interference_percentage_delta"]
        <= X4D1_INTERFERENCE_CEILING_PERCENT
    )
    expected_overall = (
        row["same_host"]
        and wall_pass
        and counter_pass
        and g1_pass
        and row["response_bytes_unchanged"]
        and interference_pass
        and inherited_pass
    )
    gate_word = "PASS" if expected_overall else "FAIL"
    expected_verdict = (
        f"{gate_word} — FLATNESS IN k: settlement_wall(k=16) <= 1.30 x "
        "settlement_wall(k=1), with equal initial_encoded_symbols_read and "
        "combined_codeword_symbols"
    )
    return (
        _x4d_exact_int(row["schema"], 1)
        and row["milestone"] == X4D1_FLATNESS_MILESTONE
        and _x4d_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["producer_source_sha256"] == X4D1_FLATNESS_PRODUCER_SHA256
        and row["profile"] == X4D_PHASE3_PROFILE
        and row["protocol"] == X4D_PHASE3_PROTOCOL
        and row["design_sha256"] == X4D1_DESIGN_SHA256
        and row["same_host"] is True
        and row["wall_semantics"] == X4D1_WALL_SEMANTICS
        and math.isclose(
            row["settlement_wall_ratio_k16_over_k1"],
            ratio,
            rel_tol=1e-15,
            abs_tol=1e-15,
        )
        and row["flatness_ceiling"] == X4D1_FLATNESS_CEILING
        and row["wall_flatness_pass"] is wall_pass
        and row["initial_encoded_symbols_equal"] is initial_equal
        and row["combined_codeword_symbols_equal"] is combined_equal
        and row["physical_counter_gate_pass"] is counter_pass
        and row["g1_rerun_pass"] is g1_pass
        and row["response_bytes_unchanged"] is True
        and row["interference_ceiling_percentage_delta"]
        == X4D1_INTERFERENCE_CEILING_PERCENT
        and row["interference_rerun_pass"] is interference_pass
        and row["inherited_settlement_gates_pass"] is inherited_pass
        and row["binding_gate_verdict_verbatim"] == expected_verdict
        and informative["lower_s"] == 288.0
        and informative["upper_s"] == 307.0
        and informative["k16_at_or_below_upper"]
        is (k16["settlement_wall_s"] <= 307.0)
        and informative["affects_binding_gate"] is False
        and informative["policy"]
        == "Informative only: a 350 s k=16 wall with a green flatness gate is PASS with a note, not FAIL"
        and row["historical_rows_modified"] is False
        and row["overall_pass"] is expected_overall
    )


def validate_x4d1_flatness(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4d1_flatness_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4_v4_pod_result_valid(row: dict[str, Any]) -> bool:
    machine = row.get("machine")
    frozen = row.get("frozen")
    inventory = row.get("physical_inventory")
    probes = row.get("production_commit_probe")
    streaming = row.get("informative_streaming_commit")
    recompute = row.get("informative_per_query_cohort_recompute")
    gpu = row.get("informative_gpu_assisted_streaming_commit")
    gate = row.get("gate")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4-v4-A100-production-record"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("pod_profile") == X4_V4_POD_PROFILE
        and row.get("protocol_or_parameter_change") is False
        and isinstance(machine, dict)
        and machine.get("provider") == "RunPod"
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
        and machine.get("timing_policy") == "wall-only+counters; no CUDA-event timing"
        and machine.get("memory_bytes", 0) > X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES
        and machine.get("persistent_volume_available_bytes", 0)
        > X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES
        and isinstance(frozen, dict)
        and frozen.get("profile") == X4_V4_PROFILE
        and frozen.get("design_sha256") == X4_V4_DESIGN_SHA256
        and frozen.get("frozen_design_baseline_sha256")
        == X4_V4_FROZEN_BASELINE_SHA256
        and frozen.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and frozen.get("note6_sha256") == X4_V4_NOTE6_SHA256
        and frozen.get("rate") == "1/8"
        and frozen.get("query_count") == 111
        and frozen.get("maximum_claim_union") == 3_320
        and frozen.get("opened_symbols") == 27_564
        and frozen.get("real_sibling_digests") == 67_930
        and frozen.get("pcs_bytes") == X4_V4_PCS_BYTES
        and frozen.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and frozen.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and frozen.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and frozen.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and frozen.get("soundness_new_terms") == 0
        and isinstance(inventory, dict)
        and inventory.get("source_equivalent_unpadded_floor_bytes")
        == X4_V4_SOURCE_FLOOR_BYTES
        and inventory.get("coefficient_bytes") == X4_V4_COEFFICIENT_BYTES
        and inventory.get("physical_padded_first_oracle_bytes")
        == X4_V4_PHYSICAL_ORACLE_BYTES
        and inventory.get("inner_merkle_digests") == X4_V4_INNER_MERKLE_DIGESTS
        and inventory.get("outer_merkle_digests") == X4_V4_OUTER_MERKLE_DIGESTS
        and inventory.get("merkle_digest_bytes") == X4_V4_MERKLE_BYTES
        and inventory.get("bytes_per_materialization") == X4_V4_MATERIALIZATION_BYTES
        and inventory.get("bytes_recomputed_per_response")
        == X4_V4_RESPONSE_RECOMPUTE_BYTES
        and inventory.get("persistent_coefficients_plus_roots_bytes")
        == X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES
        and inventory.get("maximum_current_cohort_working_set_bytes")
        == X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES
        and isinstance(inventory.get("cohorts"), list)
        and [cohort.get("name") for cohort in inventory["cohorts"]]
        == [
            "Wext-mu26-global-tied-roles",
            "Wext-mu22-all-layers",
            "Wext-mu20-layers-and-position",
            "auxiliary-ell17",
            "auxiliary-ell16",
        ]
    ):
        return False
    return (
        isinstance(probes, list)
        and len(probes) == 4
        and [probe.get("role") for probe in probes]
        == ["warmup", "measured-1", "measured-2", "measured-3"]
        and all(probe.get("exact_cohort") == "Wext-mu26-global-tied-roles" for probe in probes)
        and all(probe.get("domain_log2") == 30 for probe in probes)
        and all(probe.get("present_slots") == 2 for probe in probes)
        and all(probe.get("structural_slots") == 2 for probe in probes)
        and all(probe.get("ceiling_s") == 15.0 for probe in probes)
        and all(probe.get("completed") is False for probe in probes)
        and all(probe.get("timed_out") is True for probe in probes)
        and all(probe.get("observed_wall_s", 0) >= 15.0 for probe in probes)
        and all(probe.get("h2d_bytes") == 0 for probe in probes)
        and all(probe.get("d2h_bytes") == 0 for probe in probes)
        and all(probe.get("peak_vram_bytes") == 0 for probe in probes)
        and isinstance(streaming, dict)
        and streaming.get("status")
        == "MEASURED_EXACT_AUX17_ANCHOR; FULL_FLOOR_BLOCKED_BY_G4_TIMEOUT"
        and streaming.get("warmup_count") == 1
        and streaming.get("measured_candidates") == 3
        and len(streaming.get("candidate_wall_s", [])) == 3
        and streaming.get("selected_upper_median_wall_s", 0) > 0
        and streaming.get("measured_first_oracle_bytes_per_candidate") == 33_554_432
        and streaming.get("measured_merkle_bytes_per_candidate") == 167_772_128
        and streaming.get("selected_first_oracle_bytes_per_s", 0) > 0
        and streaming.get("projected_unpadded_floor_wall_s_at_measured_rate", 0) > 0
        and streaming.get("projected_physical_padded_oracle_wall_s_at_measured_rate", 0) > 0
        and streaming.get("full_31_9gb_pass_completed") is False
        and isinstance(recompute, dict)
        and recompute.get("query_count_per_candidate") == 1
        and len(recompute.get("candidate_wall_s", [])) == 3
        and recompute.get("selected_upper_median_wall_s", 0) > 0
        and recompute.get("source_bytes_read_per_query") == 4_194_304
        and recompute.get("oracle_bytes_recomputed_per_query") == 33_554_432
        and recompute.get("merkle_bytes_recomputed_per_query") == 167_772_128
        and recompute.get("total_logical_bytes_per_query") == 205_520_864
        and recompute.get("root_checked") is True
        and isinstance(gpu, dict)
        and gpu.get("available") is False
        and gpu.get("measured") is False
        and isinstance(gate, dict)
        and gate.get("g1_lean", "").startswith("PASS")
        and gate.get("g2_full_production_correctness", "").startswith("NOT EVALUATED")
        and gate.get("g3_communication", "").startswith("PASS")
        and gate.get("g4_commit", "").startswith("FAIL")
        and gate.get("g4_open", "").startswith("NOT EVALUATED")
        and gate.get("g4_verify", "").startswith("NOT EVALUATED")
        and gate.get("g6_storage_traffic", "").startswith("NOT EVALUATED AS PASS")
        and gate.get("overall_x4")
        == "FAIL — conjunctive G4 commit gate failed; no threshold was relaxed"
    )


def validate_x4_v4_pod_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_pod_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4b_upper_median(values: list[float]) -> float:
    return sorted(values)[len(values) // 2]


def _x4b_close(left: Any, right: Any, tolerance: float = 1e-9) -> bool:
    return (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
        and math.isfinite(float(left))
        and math.isfinite(float(right))
        and abs(float(left) - float(right)) <= tolerance * max(1.0, abs(float(right)))
    )


def _x4b_open_policy_valid(
    row: Any,
    *,
    omitted: int,
    cache_bytes: int,
    saved_bytes: int,
    traffic: dict[str, int],
) -> bool:
    if not isinstance(row, dict):
        return False
    opens = row.get("candidate_open_wall_s")
    verifies = row.get("candidate_verify_wall_s")
    return (
        row.get("bottom_outer_levels_omitted") == omitted
        and row.get("logical_outer_cache_bytes") == cache_bytes
        and row.get("cache_bytes_saved_vs_full") == saved_bytes
        and row.get("warmup_count") == 1
        and isinstance(opens, list)
        and len(opens) >= 3
        and all(isinstance(value, (int, float)) and value > 0 for value in opens)
        and _x4b_close(row.get("selected_upper_median_open_wall_s"), _x4b_upper_median(opens))
        and row.get("open_ceiling_s") == X4B_OPEN_CEILING_S
        and row.get("open_pass")
        is (row.get("selected_upper_median_open_wall_s", math.inf) <= X4B_OPEN_CEILING_S)
        and isinstance(verifies, list)
        and len(verifies) >= 3
        and all(isinstance(value, (int, float)) and value > 0 for value in verifies)
        and _x4b_close(
            row.get("selected_upper_median_verify_wall_s"), _x4b_upper_median(verifies)
        )
        and row.get("verify_ceiling_s") == X4B_VERIFY_CEILING_S
        and row.get("verify_pass")
        is (row.get("selected_upper_median_verify_wall_s", math.inf) <= X4B_VERIFY_CEILING_S)
        and row.get("traffic_per_open") == traffic
        and row.get("encoded_bytes") == X4_V4_PACKED_OPENING_BYTES
        and isinstance(row.get("encoded_blake3"), str)
        and len(row["encoded_blake3"]) == 64
    )


def _x4b_local_result_valid(row: dict[str, Any]) -> bool:
    cpu = row.get("cpu_full_node_pipeline")
    sparse = row.get("sparse_artifacts")
    full = row.get("persisted_open_full_cache")
    degraded = row.get("persisted_open_ram_degraded")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4b-local-CPU-persisted-opening-preflight"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("pod_profile") == X4B_POD_PROFILE
        and row.get("design_sha256") == X4B_DESIGN_SHA256
        and row.get("source_policy") == "PersistedOracle (record eligible)"
        and row.get("audit_recompute_refused") is True
        and row.get("query_count") == 111
        and row.get("query_draws_blake3") == X4B_QUERY_TAPE_BLAKE3
        and isinstance(row.get("profile_digest"), str)
        and len(row["profile_digest"]) == 64
        and isinstance(cpu, dict)
    ):
        return False
    scope = cpu.get("measurement_scope", "")
    candidates = cpu.get("candidates")
    if not (
        all(word in scope for word in ("serialization", "allocations", "hash_many"))
        and cpu.get("pinned_workers") == 1
        and cpu.get("warmup_count") == 1
        and isinstance(candidates, list)
        and len(candidates) >= 5
        and cpu.get("measured_candidates") == len(candidates)
        and cpu.get("canonical_frame_bytes") == X4B_CPU_CANONICAL_BYTES
        and cpu.get("logical_oracle_bytes") == 33_554_432
        and cpu.get("hash_calls") == X4B_CPU_HASH_CALLS
        and cpu.get("gate_bytes_per_s_per_core") == X4B_CPU_GATE_BPS
        and cpu.get("local_gate_comparison_only") is True
        and isinstance(cpu.get("root_hex"), str)
        and len(cpu["root_hex"]) == 64
    ):
        return False
    walls: list[float] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        wall = candidate.get("wall_s")
        allocator = candidate.get("allocator")
        if not (
            isinstance(wall, (int, float))
            and wall > 0
            and _x4b_close(
                candidate.get("canonical_frame_bytes_per_s"), X4B_CPU_CANONICAL_BYTES / wall
            )
            and _x4b_close(candidate.get("hash_calls_per_s"), X4B_CPU_HASH_CALLS / wall)
            and isinstance(allocator, dict)
            and allocator.get("allocations", 0) > 0
            and allocator.get("reallocations", 0) > 0
            and allocator.get("cumulative_requested_bytes", 0) > 0
        ):
            return False
        walls.append(float(wall))
    selected_wall = _x4b_upper_median(walls)
    selected_bps = X4B_CPU_CANONICAL_BYTES / selected_wall
    cpu_pass = selected_bps >= X4B_CPU_GATE_BPS
    if not (
        _x4b_close(cpu.get("selected_upper_median_wall_s"), selected_wall)
        and _x4b_close(cpu.get("selected_canonical_frame_bytes_per_s"), selected_bps)
        and cpu.get("local_gate_met") is cpu_pass
        and isinstance(sparse, dict)
        and sparse.get("file_count") == 32
        and sparse.get("logical_bytes") == 94_128_570_240
        and sparse.get("allocated_bytes", -1) >= 0
    ):
        return False
    full_ok = _x4b_open_policy_valid(
        full,
        omitted=0,
        cache_bytes=X4B_FULL_INITIAL_CACHE_BYTES + X4B_FULL_FOLD_CACHE_BYTES,
        saved_bytes=0,
        traffic={
            "oracle_file_bytes_read": 875_328,
            "outer_cache_bytes_read": 1_930_304,
            "inner_trees_rebuilt": 6_720,
            "outer_frontier_leaves_rebuilt": 5_610,
            "outer_internal_nodes_rebuilt": 0,
        },
    )
    degraded_ok = _x4b_open_policy_valid(
        degraded,
        omitted=1,
        cache_bytes=X4B_DEGRADED_INITIAL_CACHE_BYTES + X4B_DEGRADED_FOLD_CACHE_BYTES,
        saved_bytes=35_727_081_344,
        traffic={
            "oracle_file_bytes_read": 1_737_728,
            "outer_cache_bytes_read": 1_756_992,
            "inner_trees_rebuilt": 17_552,
            "outer_frontier_leaves_rebuilt": 16_442,
            "outer_internal_nodes_rebuilt": 5_416,
        },
    )
    byte_identity = (
        isinstance(full, dict)
        and isinstance(degraded, dict)
        and full.get("encoded_blake3") == degraded.get("encoded_blake3")
        and row.get("full_and_degraded_openings_byte_identical") is True
    )
    expected_pass = cpu_pass and full_ok and degraded_ok and byte_identity
    return (
        full_ok
        and degraded_ok
        and byte_identity
        and row.get("local_pre_pod_gate_pass") is expected_pass
        and expected_pass
        and "125 GiB" in row.get("ram_guidance", "")
    )


def validate_x4b_local_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4b_local_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4b_accelerator_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and row.get("timing_method") == "wall-only-counters"
        and row.get("phase_attribution_available") is False
        and row.get("timing_event_api_calls") == 0
        and row.get("timing_records") == 0
        and row.get("peak_device_bytes", X4B_DEVICE_BYTE_CEILING + 1)
        <= X4B_DEVICE_BYTE_CEILING
        and row.get("h2d_bytes", -1) >= 0
        and row.get("d2h_bytes", -1) >= 0
        and row.get("device_generated_bytes", -1) >= 0
        and row.get("device_zeroed_bytes", -1) >= 0
    )


def _x4b_initial_pass_valid(row: Any, *, retained: bool) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("wall_s"), (int, float))
        and row["wall_s"] > 0
        and row.get("peak_rss_bytes", 0) > 0
        and isinstance(row.get("process_io"), dict)
        and _x4b_accelerator_valid(row.get("accelerator"))
        and isinstance(row.get("cohorts"), list)
        and len(row["cohorts"]) == 5
        and [cohort.get("name") for cohort in row["cohorts"]]
        == [
            "Wext-mu26-global-tied-roles",
            "Wext-mu22-all-layers",
            "Wext-mu20-layers-and-position",
            "auxiliary-ell17",
            "auxiliary-ell16",
        ]
        and row.get("totals", {}).get("coefficient_bytes_persisted") == 9_618_587_648
        and row.get("totals", {}).get("oracle_bytes_persisted") == 76_948_701_184
        and row.get("totals", {}).get("root_bytes_persisted") == 160
        and row.get("totals", {}).get("persistent_artifact_bytes") == X4B_DURABLE_BYTES
        and row.get("reconciliation_pass") is True
        and row.get("artifacts_retained") is retained
    )


def _x4b_isolated_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("wall_s"), (int, float))
        and row["wall_s"] > 0
        and row.get("ceiling_s") == X4B_COMMIT_CEILING_S
        and _x4b_close(row.get("margin_s"), X4B_COMMIT_CEILING_S - row["wall_s"])
        and _x4b_close(
            row.get("margin_percent"),
            100.0 * (X4B_COMMIT_CEILING_S - row["wall_s"]) / X4B_COMMIT_CEILING_S,
        )
        and row.get("pass") is (row["wall_s"] <= X4B_COMMIT_CEILING_S)
        and row.get("reconciliation_pass") is True
        and _x4b_accelerator_valid(row.get("accelerator"))
        and isinstance(row.get("root_hex"), str)
        and len(row["root_hex"]) == 64
    )


def _x4b_response_candidate_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and row.get("accepted") is True
        and row.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and row.get("opened_symbols") == 27_564
        and row.get("real_sibling_digests") == 67_930
        and isinstance(row.get("seal_wall_s"), (int, float))
        and row["seal_wall_s"] > 0
        and isinstance(row.get("open_wall_s"), (int, float))
        and row["open_wall_s"] > 0
        and isinstance(row.get("verify_wall_s"), (int, float))
        and row["verify_wall_s"] > 0
        and row.get("g6_reconciliation_pass") is True
        and _x4b_accelerator_valid(row.get("accelerator_seal"))
        and row.get("metrics", {}).get("recomputed_source_bytes_read") == 0
        and row.get("metrics", {}).get("recomputed_oracle_bytes") == 0
        and row.get("metrics", {}).get("recomputed_merkle_bytes") == 0
        and row.get("metrics", {}).get("persisted_oracle_bytes_read", 0) > 0
    )


def _x4b_pod_result_valid(row: dict[str, Any]) -> bool:
    machine = row.get("machine")
    frozen = row.get("frozen")
    cache = row.get("cache_policy")
    correctness = row.get("correctness")
    full = row.get("full_pass_commit")
    isolated = row.get("isolated_wext_mu26_commit")
    artifacts = row.get("final_artifacts")
    opening = row.get("persisted_response")
    codec = row.get("codec_reference")
    gate = row.get("gate")

    def typed_sample_valid(item: Any) -> bool:
        return (
            isinstance(item, dict)
            and item.get("all_equal") is True
            and item.get("ntt_symbols_checked", 0) > 0
            and item.get("typed_inner_leaves_checked", 0) > 0
            and item.get("typed_inner_nodes_checked", 0) > 0
            and item.get("typed_inner_roots_checked") == 1
            and item.get("typed_outer_leaves_checked", 0) >= 8
            and item.get("outer_levels_checked", 0) > 0
        )
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4b-A100-production-record"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("pod_profile") == X4B_POD_PROFILE
        and row.get("protocol_or_parameter_change") is False
        and row.get("audit_recompute_refused") is True
        and row.get("draw_before_complete_seal_rejected") is True
        and isinstance(machine, dict)
        and machine.get("provider") == "RunPod"
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
        and machine.get("timing_policy") == "wall-only+counters; no CUDA-event timing"
        and machine.get("persistent_volume_bytes", 0) >= X4B_MIN_VOLUME_BYTES
        and isinstance(frozen, dict)
        and frozen.get("design_sha256") == X4B_DESIGN_SHA256
        and frozen.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and frozen.get("amendment5_preflight_sha256")
        == "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499"
        and isinstance(frozen.get("local_preflight_sha256"), str)
        and len(frozen["local_preflight_sha256"]) == 64
        and frozen.get("profile") == X4_V4_PROFILE
        and frozen.get("rate") == "1/8"
        and frozen.get("query_count") == 111
        and frozen.get("maximum_claim_union") == 3_320
        and frozen.get("opened_symbols") == 27_564
        and frozen.get("real_sibling_digests") == 67_930
        and frozen.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and frozen.get("pcs_bytes") == X4_V4_PCS_BYTES
        and frozen.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and frozen.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and frozen.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and frozen.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and frozen.get("soundness_new_terms") == 0
        and isinstance(frozen.get("note6"), dict)
        and frozen["note6"].get("passed") is True
        and frozen["note6"].get("first_action") is True
        and isinstance(frozen["note6"].get("sha256"), str)
        and len(frozen["note6"]["sha256"]) == 64
        and _x4b_local_result_valid(row.get("local_preflight_of_record", {}))
        and _x4b_local_result_valid(row.get("pod_host_cpu_preflight", {}))
        and isinstance(cache, dict)
    ):
        return False
    if cache.get("name") == "full":
        cache_ok = (
            cache.get("bottom_levels_omitted") == 0
            and cache.get("retained_initial_outer_cache_bytes")
            == X4B_FULL_INITIAL_CACHE_BYTES
            and cache.get("retained_fold_outer_cache_bytes") == X4B_FULL_FOLD_CACHE_BYTES
        )
    elif cache.get("name") == "ram-degraded-one-level":
        cache_ok = (
            cache.get("bottom_levels_omitted") == 1
            and cache.get("retained_initial_outer_cache_bytes")
            == X4B_DEGRADED_INITIAL_CACHE_BYTES
            and cache.get("retained_fold_outer_cache_bytes")
            == X4B_DEGRADED_FOLD_CACHE_BYTES
        )
    else:
        cache_ok = False
    cache_ok = cache_ok and cache.get("retained_total_outer_cache_bytes") == (
        cache.get("retained_initial_outer_cache_bytes", 0)
        + cache.get("retained_fold_outer_cache_bytes", 0)
    )
    if not (
        cache_ok
        and isinstance(correctness, dict)
        and correctness.get("synthetic_preflight_before_full_pass") is True
        and correctness.get("all_equal") is True
        and len(correctness.get("contexts", [])) == 4
        and all(item.get("equal") is True for item in correctness["contexts"])
        and len(correctness.get("synthetic", [])) == 5
        and all(item.get("equal") is True for item in correctness["synthetic"])
        and len(correctness.get("complete_aux_roots", [])) == 2
        and all(typed_sample_valid(item) for item in correctness["complete_aux_roots"])
        and len(correctness.get("larger_cohort_samples", [])) == 3
        and all(typed_sample_valid(item) for item in correctness["larger_cohort_samples"])
        and isinstance(full, dict)
        and full.get("hard_ceiling") is None
        and full.get("status")
        == "MEASURED/INFORMATIVE; no hard ceiling in runpod-a100-x4b-v1"
        and _x4b_initial_pass_valid(full.get("warmup"), retained=False)
        and isinstance(full.get("measured"), list)
        and len(full["measured"]) == 3
        and all(_x4b_initial_pass_valid(item, retained=False) for item in full["measured"])
        and _x4b_close(
            full.get("selected_upper_median_wall_s"),
            _x4b_upper_median([item["wall_s"] for item in full["measured"]]),
        )
        and _x4b_initial_pass_valid(full.get("final_materialization"), retained=True)
        and isinstance(isolated, dict)
        and _x4b_isolated_valid(isolated.get("warmup"))
        and isinstance(isolated.get("measured"), list)
        and len(isolated["measured"]) == 3
        and all(_x4b_isolated_valid(item) for item in isolated["measured"])
    ):
        return False
    isolated_selected = _x4b_upper_median([item["wall_s"] for item in isolated["measured"]])
    isolated_pass = isolated_selected <= X4B_COMMIT_CEILING_S
    if not (
        _x4b_close(isolated.get("selected_upper_median_wall_s"), isolated_selected)
        and isolated.get("ceiling_s") == X4B_COMMIT_CEILING_S
        and _x4b_close(isolated.get("margin_s"), X4B_COMMIT_CEILING_S - isolated_selected)
        and isolated.get("pass") is isolated_pass
        and isinstance(artifacts, dict)
        and artifacts.get("page_cache_dontneed_bytes") == 9_618_587_808
        and artifacts.get("page_cache_advice_calls") == 10
        and artifacts.get("footprint", {}).get("coefficient_bytes") == 9_618_587_648
        and artifacts.get("footprint", {}).get("oracle_bytes") == 76_948_701_184
        and artifacts.get("footprint", {}).get("root_bytes") == 160
        and artifacts.get("footprint", {}).get("durable_bytes") == X4B_DURABLE_BYTES
        and artifacts.get("footprint", {}).get("all_lengths_and_bindings_checked") is True
        and isinstance(opening, dict)
        and opening.get("source_policy")
        == "PersistedOracle (record eligible); AuditRecompute refused"
        and _x4b_response_candidate_valid(opening.get("warmup"))
        and isinstance(opening.get("measured"), list)
        and len(opening["measured"]) == 3
        and all(_x4b_response_candidate_valid(item) for item in opening["measured"])
    ):
        return False
    selected_open = _x4b_upper_median([item["open_wall_s"] for item in opening["measured"]])
    selected_verify = _x4b_upper_median([item["verify_wall_s"] for item in opening["measured"]])
    open_pass = selected_open <= X4B_OPEN_CEILING_S
    verify_pass = selected_verify <= X4B_VERIFY_CEILING_S
    communication_pass = opening.get("all_byte_counts_exact") is True
    g6_pass = opening.get("all_g6_reconciled") is True
    hardware_pass = (
        machine.get("memory_bytes", 0) >= X4B_BASELINE_RAM_BYTES
        and machine.get("persistent_volume_bytes", 0) >= X4B_MIN_VOLUME_BYTES
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
    )
    cpu_pass = (
        row["pod_host_cpu_preflight"]["cpu_full_node_pipeline"]
        ["selected_canonical_frame_bytes_per_s"]
        >= X4B_CPU_GATE_BPS
    )
    overall_pass = (
        cpu_pass
        and correctness["all_equal"]
        and isolated_pass
        and open_pass
        and verify_pass
        and opening.get("all_accepted") is True
        and communication_pass
        and g6_pass
        and hardware_pass
    )
    expected_prefix = "PASS" if overall_pass else "FAIL"
    return (
        _x4b_close(opening.get("selected_upper_median_open_wall_s"), selected_open)
        and _x4b_close(opening.get("selected_upper_median_verify_wall_s"), selected_verify)
        and opening.get("open_pass") is open_pass
        and opening.get("verify_pass") is verify_pass
        and opening.get("all_accepted") is True
        and isinstance(codec, dict)
        and codec.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and codec.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and codec.get("complete_pcs_bytes") == X4_V4_PCS_BYTES
        and codec.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and codec.get("golden_decode_exact") is True
        and codec.get("exact_match") is True
        and isinstance(gate, dict)
        and gate.get("overall_x4b", "").startswith(expected_prefix)
        and gate.get("historical_x4", "").startswith("FAIL IMMUTABLE")
        and row.get("historical_baseline", {}).get("immutable") is True
        and row.get("historical_baseline", {}).get("verdict")
        == "G4 COMMIT FAIL; OVERALL X4 FAIL"
    )


def validate_x4b_pod_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4b_pod_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4c_state_bytes(domain_log2: int) -> tuple[int, int]:
    outer_len = 1 << domain_log2
    rounds = domain_log2 - 3
    return (outer_len - 8) * 16, (outer_len - 8 - rounds) * 32


def _x4c_timing_valid(timing: Any) -> bool:
    if not isinstance(timing, dict):
        return False
    categories = [
        timing.get("query_gather_wall_ns"),
        timing.get("hashing_path_assembly_wall_ns"),
        timing.get("encode_serialize_wall_ns"),
        timing.get("teardown_wall_ns"),
    ]
    total = timing.get("instrumented_total_wall_ns")
    caller = timing.get("caller_wall_ns")
    return (
        all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in categories)
        and isinstance(total, int)
        and total >= sum(categories)
        and isinstance(caller, int)
        and caller >= total
    )


def _x4c_phase1_result_valid(row: dict[str, Any]) -> bool:
    immutable = row.get("immutable")
    instrumentation = row.get("instrumentation")
    io = row.get("io_postdiction")
    opened = row.get("open_postdiction")
    scales = row.get("synthetic_scales")
    projection = row.get("analytic_pod_scale_projection")
    if not (
        row.get("schema") == 2
        and row.get("milestone") == X4C_PHASE1_MILESTONE
        and row.get("date") == "2026-07-23"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("phase") == 1
        and row.get("pod_contacted") is False
        and row.get("preregistration_v1_sha256")
        == X4C_PREREGISTRATION_V1_SHA256
        and row.get("design_sha256") == X4C_DESIGN_SHA256
        and "predeclared CONFIRMED" in row.get("interpretation_correction", "")
        and isinstance(immutable, dict)
        and immutable.get("protocol_profile") == X4_V4_PROFILE
        and immutable.get("rate") == "1/8"
        and immutable.get("query_count") == 111
        and immutable.get("pcs_bytes") == X4_V4_PCS_BYTES
        and immutable.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and immutable.get("proof_format_changed") is False
        and immutable.get("root_changed") is False
        and immutable.get("lean_changed") is False
        and immutable.get("soundness_changed") is False
        and isinstance(instrumentation, dict)
        and all(
            isinstance(instrumentation.get(key), str) and instrumentation[key]
            for key in (
                "query_gather",
                "hashing_path_assembly",
                "encode_serialize",
                "teardown",
                "timer_unit",
                "proof_or_transcript_effect",
            )
        )
    ):
        return False

    modeled_read = 34_359_738_368 + 68_719_476_672
    modeled_write = 4_294_967_296 + 34_359_738_368 + 68_719_476_704 + 32
    modeled_io = modeled_read + modeled_write
    observed_read = 103_079_235_584
    observed_write = 107_374_211_072
    observed_io = observed_read + observed_write
    selected_wall = 254.861_527_720
    aggregate_rate = observed_io / selected_wall
    postdicted_wall = modeled_io / aggregate_rate
    if not (
        isinstance(io, dict)
        and io.get("source_record")
        == "benchmarks/results/x4b-a100-production-2026-07-22-6c6907a.json"
        and io.get("source_record_sha256")
        == "63f4a97b263e4d09649d5a6ede5af1ba420efdcc78bb30f54b9f8cf200cfe6e0"
        and io.get("coefficient_bytes") == 4_294_967_296
        and io.get("oracle_bytes") == 34_359_738_368
        and io.get("staging_bytes_read") == 68_719_476_672
        and io.get("staging_bytes_written") == 68_719_476_704
        and io.get("modeled_host_read_bytes") == modeled_read
        and io.get("modeled_host_write_bytes") == modeled_write
        and io.get("modeled_physical_io_bytes") == modeled_io
        and io.get("observed_process_read_bytes") == observed_read
        and io.get("observed_process_write_bytes") == observed_write
        and io.get("observed_physical_io_bytes") == observed_io
        and io.get("reconciliation_delta_bytes") == observed_io - modeled_io
        and _x4b_close(io.get("selected_wall_s"), selected_wall)
        and _x4b_close(io.get("observed_aggregate_bytes_per_s"), aggregate_rate)
        and _x4b_close(io.get("postdicted_wall_s"), postdicted_wall)
        and _x4b_close(
            io.get("postdiction_residual_s"), selected_wall - postdicted_wall
        )
        and io.get("h2d_bytes") == 107_374_217_152
        and io.get("d2h_bytes") == 103_079_215_072
        and io.get("pcie_transfer_bytes") == 210_453_432_224
        and "no fitted" in io.get("model_policy", "")
    ):
        return False

    production_state = (
        X4C_PRODUCTION_FOLD_CODEWORD_BYTES + X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
    )
    implied = X4C_X4B_OPEN_WALL_S - X4C_NO_TEARDOWN_OPEN_ANCHOR_S
    if not (
        isinstance(opened, dict)
        and _x4b_close(opened.get("observed_open_wall_s"), X4C_X4B_OPEN_WALL_S)
        and _x4b_close(
            opened.get("same_host_exact_geometry_no_sealed_state_anchor_s"),
            X4C_NO_TEARDOWN_OPEN_ANCHOR_S,
        )
        and _x4b_close(opened.get("implied_lifecycle_debt_s"), implied)
        and _x4b_close(opened.get("implied_lifecycle_share"), implied / X4C_X4B_OPEN_WALL_S)
        and opened.get("issue_query_oracle_bytes_read") == 724_608
        and opened.get("issue_query_outer_cache_bytes_read") == 507_008
        and opened.get("inner_trees_rebuilt") == 2_220
        and opened.get("sealed_fold_codeword_bytes")
        == X4C_PRODUCTION_FOLD_CODEWORD_BYTES
        and opened.get("sealed_fold_outer_cache_bytes")
        == X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
        and opened.get("sealed_state_bytes") == production_state
        and _x4b_close(
            opened.get("lifecycle_debt_dominance_threshold_s"), implied / 2.0
        )
        and ">50%" in opened.get("hypothesis_decision_rule", "")
        and "no regression or fitted intercept"
        in opened.get("hypothesis_decision_rule", "")
    ):
        return False

    if not isinstance(scales, list) or [
        item.get("domain_log2") for item in scales if isinstance(item, dict)
    ] != X4C_SYNTHETIC_DOMAIN_LOG2:
        return False
    for scale in scales:
        if not isinstance(scale, dict):
            return False
        domain_log2 = scale["domain_log2"]
        expected_codeword, expected_cache = _x4c_state_bytes(domain_log2)
        expected_state = expected_codeword + expected_cache
        candidates = scale.get("candidates")
        selected = scale.get("selected_upper_median")
        if not (
            scale.get("outer_len") == 1 << domain_log2
            and scale.get("warmup_count") == 1
            and scale.get("measured_candidates") == X4C_MEASURED_CANDIDATES
            and isinstance(candidates, list)
            and len(candidates) == X4C_MEASURED_CANDIDATES
            and isinstance(selected, dict)
            and scale.get("all_accepted") is True
            and scale.get("exact_state_accounting") is True
        ):
            return False
        expected_trees = domain_log2 - 3
        expected_level_vectors = (domain_log2 + 2) * (domain_log2 - 3) // 2
        for candidate in candidates:
            allocator = candidate.get("allocator") if isinstance(candidate, dict) else None
            if not (
                isinstance(candidate, dict)
                and candidate.get("sealed_fold_codeword_bytes") == expected_codeword
                and candidate.get("sealed_fold_outer_cache_bytes") == expected_cache
                and candidate.get("sealed_state_bytes") == expected_state
                and candidate.get("sealed_fold_tree_count") == expected_trees
                and candidate.get("sealed_fold_outer_level_vectors")
                == expected_level_vectors
                and _x4c_timing_valid(candidate.get("timing"))
                and isinstance(allocator, dict)
                and allocator.get("allocations", 0) > 0
                and allocator.get("deallocations", 0) > 0
                and allocator.get("cumulative_requested_bytes", 0) > 0
                and allocator.get("cumulative_deallocated_bytes", 0) >= expected_state
                and candidate.get("accepted") is True
                and candidate.get("canonical_proof_bytes", 0) > 0
            ):
                return False
        timing_keys = (
            "query_gather_wall_ns",
            "hashing_path_assembly_wall_ns",
            "encode_serialize_wall_ns",
            "teardown_wall_ns",
            "instrumented_total_wall_ns",
            "caller_wall_ns",
        )
        for key in timing_keys:
            if selected.get(key) != _x4b_upper_median(
                [candidate["timing"][key] for candidate in candidates]
            ):
                return False

    largest = scales[-1]
    source_state = largest["candidates"][0]["sealed_state_bytes"]
    byte_scale = production_state / source_state
    teardown_candidates = [
        candidate["timing"]["teardown_wall_ns"] for candidate in largest["candidates"]
    ]
    projected_teardown = (
        largest["selected_upper_median"]["teardown_wall_ns"] * byte_scale / 1e9
    )
    projected_teardown_low = min(teardown_candidates) * byte_scale / 1e9
    projected_teardown_high = max(teardown_candidates) * byte_scale / 1e9
    dominance_threshold = implied / 2.0
    if projected_teardown_high < dominance_threshold:
        expected_disposition_code = "REFUTED_LOCAL_SYNTHETIC_DIRECT_PROJECTION"
        expected_disposition_prefix = "REFUTED at the Phase-1 evidence level:"
    elif projected_teardown_low > dominance_threshold:
        expected_disposition_code = "CONFIRMED_LOCAL_SYNTHETIC_DIRECT_PROJECTION"
        expected_disposition_prefix = "CONFIRMED at the Phase-1 evidence level:"
    else:
        expected_disposition_code = "INCONCLUSIVE_LOCAL_SYNTHETIC_DIRECT_PROJECTION"
        expected_disposition_prefix = "INCONCLUSIVE at the Phase-1 evidence level:"
    if not (
        isinstance(projection, dict)
        and "no regression" in projection.get("policy", "")
        and projection.get("source_domain_log2") == X4C_SYNTHETIC_DOMAIN_LOG2[-1]
        and projection.get("source_sealed_state_bytes") == source_state
        and projection.get("production_sealed_state_bytes") == production_state
        and _x4b_close(projection.get("byte_scale"), byte_scale)
        and _x4b_close(projection.get("projected_teardown_wall_s"), projected_teardown)
        and _x4b_close(
            projection.get("projected_teardown_wall_s_low"),
            projected_teardown_low,
        )
        and _x4b_close(
            projection.get("projected_teardown_wall_s_high"),
            projected_teardown_high,
        )
        and _x4b_close(
            projection.get("projected_teardown_share_of_lifecycle_debt"),
            projected_teardown / implied,
        )
        and _x4b_close(
            projection.get("projected_teardown_share_of_lifecycle_debt_low"),
            projected_teardown_low / implied,
        )
        and _x4b_close(
            projection.get("projected_teardown_share_of_lifecycle_debt_high"),
            projected_teardown_high / implied,
        )
        and _x4b_close(
            projection.get("same_host_no_teardown_anchor_s"),
            X4C_NO_TEARDOWN_OPEN_ANCHOR_S,
        )
        and _x4b_close(
            projection.get("projected_total_open_wall_s"),
            projected_teardown + X4C_NO_TEARDOWN_OPEN_ANCHOR_S,
        )
        and _x4b_close(
            projection.get("observed_x4b_open_wall_s"), X4C_X4B_OPEN_WALL_S
        )
        and opened.get("hypothesis_disposition_code") == expected_disposition_code
        and opened.get("hypothesis_disposition", "").startswith(
            expected_disposition_prefix
        )
        and "analytic projection only" in projection.get("hardware_transfer_warning", "")
        and row.get("hard_stop", "").startswith("PHASE 1 COMPLETE ONLY")
    ):
        return False
    return True


def validate_x4c_phase1_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4c_phase1_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4c_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _x4c_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _x4c_availability_valid(value: Any, *, required: bool) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("available"), bool)
        and isinstance(value.get("reason"), str)
        and (value["available"] is (value["reason"] == ""))
        and (not required or value["available"] is True)
    )


def _x4c_boundary_snapshot_valid(row: Any, *, require_available: bool = True) -> bool:
    if not (
        isinstance(row, dict)
        and row.get("schema") == 1
        and _x4c_nonnegative_int(row.get("seq"))
        and isinstance(row.get("label"), str)
        and bool(row["label"])
        and _x4c_nonnegative_int(row.get("monotonic_enter_ns"))
        and _x4c_nonnegative_int(row.get("monotonic_exit_ns"))
        and _x4c_nonnegative_int(row.get("snapshot_probe_wall_ns"))
        and row["monotonic_exit_ns"] >= row["monotonic_enter_ns"]
        and row["snapshot_probe_wall_ns"]
        == row["monotonic_exit_ns"] - row["monotonic_enter_ns"]
    ):
        return False

    io = row.get("process_io")
    faults = row.get("page_faults")
    memory = row.get("process_memory")
    smaps = row.get("smaps_rollup")
    allocator = row.get("allocator")
    numa = row.get("numa")
    cuda = row.get("cuda")
    ownership = row.get("sealed_ownership")
    temporary = row.get("temporary_files")
    if not all(
        isinstance(value, dict)
        for value in (
            io,
            faults,
            memory,
            smaps,
            allocator,
            numa,
            cuda,
            ownership,
            temporary,
        )
    ):
        return False

    if not (
        _x4c_availability_valid(io.get("availability"), required=require_available)
        and all(
            _x4c_nonnegative_int(io.get(key))
            for key in ("rchar", "wchar", "read_bytes", "write_bytes")
        )
        and _x4c_availability_valid(
            faults.get("availability"), required=require_available
        )
        and all(
            _x4c_nonnegative_int(faults.get(key))
            for key in ("minor_faults", "major_faults")
        )
        and _x4c_availability_valid(
            memory.get("availability"), required=require_available
        )
        and all(
            _x4c_nonnegative_int(memory.get(key))
            for key in ("rss_bytes", "locked_bytes")
        )
        and _x4c_availability_valid(
            smaps.get("availability"), required=require_available
        )
        and all(
            _x4c_nonnegative_int(smaps.get(key))
            for key in (
                "rss_bytes",
                "pss_bytes",
                "anonymous_bytes",
                "file_bytes",
                "shmem_bytes",
                "private_clean_bytes",
                "private_dirty_bytes",
                "shared_clean_bytes",
                "shared_dirty_bytes",
                "swap_bytes",
            )
        )
    ):
        return False

    allocator_fields = (
        "allocation_calls",
        "alloc_zeroed_calls",
        "reallocation_calls",
        "deallocation_calls",
        "cumulative_allocated_bytes",
        "cumulative_deallocated_bytes",
        "outstanding_requested_bytes",
        "allocator_allocated_bytes",
        "allocator_mapped_bytes",
        "arena_bytes",
        "mmap_region_bytes",
        "free_arena_bytes",
    )
    if not (
        _x4c_availability_valid(
            allocator.get("availability"), required=require_available
        )
        and all(_x4c_nonnegative_int(allocator.get(key)) for key in allocator_fields)
        and allocator["cumulative_allocated_bytes"]
        >= allocator["cumulative_deallocated_bytes"]
        and allocator["outstanding_requested_bytes"]
        == allocator["cumulative_allocated_bytes"]
        - allocator["cumulative_deallocated_bytes"]
        and allocator["allocator_mapped_bytes"]
        == allocator["arena_bytes"] + allocator["mmap_region_bytes"]
        and allocator["allocator_allocated_bytes"]
        <= allocator["allocator_mapped_bytes"]
    ):
        return False

    node_pages = numa.get("node_pages")
    if not (
        _x4c_availability_valid(numa.get("availability"), required=require_available)
        and _x4c_nonnegative_int(numa.get("page_size_bytes"))
        and (not numa["availability"]["available"] or numa["page_size_bytes"] > 0)
        and _x4c_nonnegative_int(numa.get("total_node_pages"))
        and isinstance(node_pages, dict)
        and all(
            isinstance(node, str)
            and len(node) >= 2
            and node.startswith("N")
            and node[1:].isdigit()
            and _x4c_nonnegative_int(pages)
            for node, pages in node_pages.items()
        )
        and numa["total_node_pages"] == sum(node_pages.values())
        and (not numa["availability"]["available"] or bool(node_pages))
    ):
        return False

    cuda_fields = (
        "device_workspace_bytes",
        "device_resident_bytes",
        "device_cached_bytes",
        "device_live_bytes",
        "pinned_host_bytes",
        "outstanding_operations",
    )
    if not (
        _x4c_availability_valid(cuda.get("availability"), required=require_available)
        and all(_x4c_nonnegative_int(cuda.get(key)) for key in cuda_fields)
        and isinstance(cuda.get("measurement_active"), bool)
        and isinstance(cuda.get("synchronized"), bool)
        and cuda["device_live_bytes"]
        == cuda["device_workspace_bytes"]
        + cuda["device_resident_bytes"]
        + cuda["device_cached_bytes"]
        and (not cuda["synchronized"] or cuda["outstanding_operations"] == 0)
    ):
        return False

    ownership_fields = (
        "fold_codeword_bytes",
        "fold_outer_cache_bytes",
        "other_ordinary_host_bytes",
        "ordinary_host_bytes",
        "pinned_host_bytes",
        "device_bytes",
        "file_backed_bytes",
        "owned_file_count",
        "owned_mapping_count",
        "borrowed_initial_source_file_count",
    )
    if not (
        all(_x4c_nonnegative_int(ownership.get(key)) for key in ownership_fields)
        and ownership["ordinary_host_bytes"]
        == ownership["fold_codeword_bytes"]
        + ownership["fold_outer_cache_bytes"]
        + ownership["other_ordinary_host_bytes"]
        and isinstance(ownership.get("owned_files"), list)
        and all(
            isinstance(value, str) and value for value in ownership["owned_files"]
        )
        and isinstance(ownership.get("owned_mappings"), list)
        and all(
            isinstance(value, str) and value for value in ownership["owned_mappings"]
        )
        and isinstance(ownership.get("borrowed_initial_source_files"), list)
        and all(
            isinstance(value, str) and value
            for value in ownership["borrowed_initial_source_files"]
        )
        and ownership["owned_file_count"] >= len(ownership["owned_files"])
        and ownership["owned_mapping_count"] >= len(ownership["owned_mappings"])
        and ownership["borrowed_initial_source_file_count"]
        >= len(ownership["borrowed_initial_source_files"])
        and (
            ownership["file_backed_bytes"] > 0
            or (
                ownership["owned_file_count"] == 0
                and ownership["owned_mapping_count"] == 0
            )
        )
        and (
            ownership["file_backed_bytes"] == 0
            or ownership["owned_file_count"] > 0
            or ownership["owned_mapping_count"] > 0
        )
    ):
        return False

    temporary_fields = (
        "live_file_count",
        "live_file_bytes",
        "live_directory_count",
        "cumulative_created_files",
        "cumulative_deleted_files",
        "cumulative_created_directories",
        "cumulative_deleted_directories",
    )
    return (
        all(_x4c_nonnegative_int(temporary.get(key)) for key in temporary_fields)
        and temporary["cumulative_created_files"]
        >= temporary["cumulative_deleted_files"]
        and temporary["live_file_count"]
        == temporary["cumulative_created_files"]
        - temporary["cumulative_deleted_files"]
        and temporary["cumulative_created_directories"]
        >= temporary["cumulative_deleted_directories"]
        and temporary["live_directory_count"]
        == temporary["cumulative_created_directories"]
        - temporary["cumulative_deleted_directories"]
    )


def _x4c_boundary_timeline_valid(
    boundaries: Any, *, require_available: bool = True
) -> bool:
    if not (
        isinstance(boundaries, list)
        and boundaries
        and all(
            _x4c_boundary_snapshot_valid(
                boundary, require_available=require_available
            )
            for boundary in boundaries
        )
        and [boundary["seq"] for boundary in boundaries]
        == list(range(len(boundaries)))
    ):
        return False
    monotonic_groups = {
        "process_io": ("rchar", "wchar", "read_bytes", "write_bytes"),
        "page_faults": ("minor_faults", "major_faults"),
        "allocator": (
            "allocation_calls",
            "alloc_zeroed_calls",
            "reallocation_calls",
            "deallocation_calls",
            "cumulative_allocated_bytes",
            "cumulative_deallocated_bytes",
        ),
        "temporary_files": (
            "cumulative_created_files",
            "cumulative_deleted_files",
            "cumulative_created_directories",
            "cumulative_deleted_directories",
        ),
    }
    for before, after in zip(boundaries, boundaries[1:]):
        if (
            after["monotonic_enter_ns"] < before["monotonic_exit_ns"]
            or after["monotonic_exit_ns"] < before["monotonic_exit_ns"]
        ):
            return False
        for group, fields in monotonic_groups.items():
            if any(after[group][field] < before[group][field] for field in fields):
                return False
    return True


def _x4c_context_valid(context: Any) -> bool:
    if not isinstance(context, dict):
        return False
    optional_fields = {
        "cohort_id": (0, (1 << 32) - 1),
        "fold_round": (0, 255),
        "slot_index": (0, (1 << 16) - 1),
        "initial_group_index": (0, (1 << 32) - 1),
        "outer_level": (0, 255),
    }
    for key, (minimum, maximum) in optional_fields.items():
        if key not in context:
            return False
        value = context[key]
        if value is not None and not (
            _x4c_nonnegative_int(value) and minimum <= value <= maximum
        ):
            return False
    return _x4c_nonnegative_int(context.get("segment_index"))


def _x4c_span_key(row: dict[str, Any]) -> tuple[Any, ...]:
    context = row["context"]
    return (
        row["track"],
        row["phase"],
        row["nesting"],
        context["cohort_id"],
        context["fold_round"],
        context["slot_index"],
        context["initial_group_index"],
        context["outer_level"],
        context["segment_index"],
    )


def _x4c_lifecycle_timeline_valid(
    events: Any, spans: Any, boundaries: list[dict[str, Any]]
) -> bool:
    if not (
        isinstance(events, list)
        and events
        and isinstance(spans, list)
        and spans
    ):
        return False
    boundary_by_seq = {boundary["seq"]: boundary for boundary in boundaries}
    event_by_seq: dict[int, dict[str, Any]] = {}
    stacks: dict[tuple[Any, ...], list[int]] = {}
    matched: set[tuple[tuple[Any, ...], int, int]] = set()
    for event in events:
        if not (
            isinstance(event, dict)
            and event.get("schema") == 1
            and event.get("track") in {"legacy_seal", "legacy_opening"}
            and isinstance(event.get("phase"), str)
            and event["phase"]
            in X4C_LEGACY_SEAL_PHASES | X4C_LEGACY_OPENING_PHASES
            and event.get("transition") in {"span_start", "span_end", "boundary"}
            and event.get("nesting") in {"top_level", "nested"}
            and _x4c_context_valid(event.get("context"))
            and _x4c_nonnegative_int(event.get("boundary_seq"))
            and event["boundary_seq"] in boundary_by_seq
            and event["boundary_seq"] not in event_by_seq
        ):
            return False
        if event["phase"] == "inner_hashing_path_assembly":
            if event["nesting"] != "nested" or event["track"] != "legacy_opening":
                return False
        elif event["nesting"] != "top_level":
            return False
        if (
            event["track"] == "legacy_seal"
            and event["phase"] not in X4C_LEGACY_SEAL_PHASES
        ) or (
            event["track"] == "legacy_opening"
            and event["phase"] not in X4C_LEGACY_OPENING_PHASES
        ):
            return False
        event_by_seq[event["boundary_seq"]] = event
        key = _x4c_span_key(event)
        if event["transition"] == "span_start":
            stacks.setdefault(key, []).append(event["boundary_seq"])
        elif event["transition"] == "span_end":
            starts = stacks.get(key)
            if not starts:
                return False
            start = starts.pop()
            if event["boundary_seq"] <= start:
                return False
            matched.add((key, start, event["boundary_seq"]))
    if any(starts for starts in stacks.values()):
        return False

    supplied: set[tuple[tuple[Any, ...], int, int]] = set()
    top_level_intervals: dict[str, list[tuple[int, int]]] = {
        "legacy_seal": [],
        "legacy_opening": [],
    }
    nested_intervals: list[tuple[int, int]] = []
    for span in spans:
        if not (
            isinstance(span, dict)
            and span.get("track") in {"legacy_seal", "legacy_opening"}
            and span.get("phase")
            in X4C_LEGACY_SEAL_PHASES | X4C_LEGACY_OPENING_PHASES
            and span.get("nesting") in {"top_level", "nested"}
            and _x4c_context_valid(span.get("context"))
            and _x4c_nonnegative_int(span.get("start_seq"))
            and _x4c_nonnegative_int(span.get("end_seq"))
            and span["start_seq"] in boundary_by_seq
            and span["end_seq"] in boundary_by_seq
            and span["end_seq"] > span["start_seq"]
            and _x4c_nonnegative_int(span.get("subject_wall_ns"))
            and _x4c_nonnegative_int(span.get("inclusive_wall_ns"))
            and _x4c_nonnegative_int(span.get("boundary_probe_wall_ns"))
        ):
            return False
        start = boundary_by_seq[span["start_seq"]]
        end = boundary_by_seq[span["end_seq"]]
        subject_wall = end["monotonic_enter_ns"] - start["monotonic_exit_ns"]
        inclusive_wall = end["monotonic_exit_ns"] - start["monotonic_enter_ns"]
        boundary_probe_wall = (
            start["snapshot_probe_wall_ns"] + end["snapshot_probe_wall_ns"]
        )
        if (
            span["subject_wall_ns"] != subject_wall
            or span["inclusive_wall_ns"] != inclusive_wall
            or span["boundary_probe_wall_ns"] != boundary_probe_wall
            or inclusive_wall != subject_wall + boundary_probe_wall
        ):
            return False
        key = _x4c_span_key(span)
        identity = (key, span["start_seq"], span["end_seq"])
        if identity in supplied:
            return False
        supplied.add(identity)
        interval = (span["start_seq"], span["end_seq"])
        if span["nesting"] == "nested":
            nested_intervals.append(interval)
        else:
            top_level_intervals[span["track"]].append(interval)
    if supplied != matched:
        return False

    for intervals in top_level_intervals.values():
        intervals.sort()
        if any(after[0] < before[1] for before, after in zip(intervals, intervals[1:])):
            return False
    opening_containers = [
        interval
        for span, interval in zip(spans, [(s["start_seq"], s["end_seq"]) for s in spans])
        if span.get("track") == "legacy_opening"
        and span.get("phase") in {"initial_group_opening", "fold_round_opening"}
        and span.get("nesting") == "top_level"
    ]
    if any(
        not any(parent_start <= start and end <= parent_end for parent_start, parent_end in opening_containers)
        for start, end in nested_intervals
    ):
        return False
    nested_intervals.sort()
    if any(
        after[0] < before[1]
        for before, after in zip(nested_intervals, nested_intervals[1:])
    ):
        return False

    seal_phases = {
        span["phase"] for span in spans if span["track"] == "legacy_seal"
    }
    opening_phases = {
        span["phase"] for span in spans if span["track"] == "legacy_opening"
    }
    if not (
        seal_phases == X4C_LEGACY_SEAL_PHASES
        and opening_phases == X4C_LEGACY_OPENING_PHASES
    ):
        return False
    finish_ends = [
        span["end_seq"]
        for span in spans
        if span["phase"] == "backend_finish_synchronization_boundary"
    ]
    opening_starts = [
        span["start_seq"] for span in spans if span["track"] == "legacy_opening"
    ]
    return (
        len(finish_ends) == 1
        and bool(opening_starts)
        and finish_ends[0] < min(opening_starts)
        and boundary_by_seq[finish_ends[0]]["cuda"]["synchronized"] is True
        and boundary_by_seq[finish_ends[0]]["cuda"]["outstanding_operations"] == 0
    )


def _x4c_immutable_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and row.get("protocol_profile") == X4_V4_PROFILE
        and row.get("rate") == "1/8"
        and row.get("query_count") == 111
        and row.get("pcs_bytes") == X4_V4_PCS_BYTES
        and row.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and row.get("proof_format_changed") is False
        and row.get("root_changed") is False
        and row.get("lean_changed") is False
        and row.get("soundness_changed") is False
    )


def _x4c_storage_and_machine_valid(machine: Any) -> bool:
    if not (
        isinstance(machine, dict)
        and machine.get("provider") == "RunPod"
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and _x4c_nonnegative_int(machine.get("memory_bytes"))
        and machine["memory_bytes"] >= X4C_MIN_HOST_RAM_BYTES
        and machine.get("rayon_threads") == 8
        and machine.get("commit_seal_open_unpinned") is True
        and machine.get("durable_tier")
        == "coefficients_plus_five_roots_on_persistent"
        and machine.get("local_storage_role") == "scratch_ram_spill_and_records"
        and machine.get("persistent_class") == "PERSISTENT"
    ):
        return False
    persistent = machine.get("persistent_volume")
    local = machine.get("local_non_mfs_storage")
    return (
        isinstance(persistent, dict)
        and isinstance(local, dict)
        and isinstance(persistent.get("path"), str)
        and bool(persistent["path"])
        and isinstance(local.get("path"), str)
        and bool(local["path"])
        and persistent["path"] != local["path"]
        and isinstance(persistent.get("filesystem_type"), str)
        and bool(persistent["filesystem_type"])
        and isinstance(persistent.get("mount_point"), str)
        and bool(persistent["mount_point"])
        and isinstance(local.get("filesystem_type"), str)
        and local["filesystem_type"] not in {"", "tmpfs", "ramfs", "mfs"}
        and isinstance(local.get("mount_point"), str)
        and bool(local["mount_point"])
        and persistent["mount_point"] != local["mount_point"]
        and _x4c_nonnegative_int(persistent.get("available_bytes"))
        and _x4c_nonnegative_int(local.get("available_bytes"))
        and local["available_bytes"] >= X4C_MIN_LOCAL_STORAGE_BYTES
    )


def _x4c_legacy_causal_result_valid(row: dict[str, Any]) -> bool:
    correction = row.get("terminology_correction")
    candidates = row.get("candidates")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == X4C_LEGACY_CAUSAL_MILESTONE
        and row.get("phase") == 2
        and row.get("pod_profile") == X4C_POD_PROFILE
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and _x4c_immutable_valid(row.get("immutable"))
        and _x4c_storage_and_machine_valid(row.get("machine"))
        and isinstance(correction, dict)
        and correction.get("byte_reconciliation_difference_bytes") == 49_216
        and correction.get("byte_reconciliation_classification")
        == "EXACT_BYTE_RECONCILIATION"
        and correction.get("reconstructed_wall_residual_ns") == 59_601
        and correction.get("aggregate_rate_derived_from_same_wall") is True
        and correction.get("independent_causal_timing_evidence") is False
        and correction.get("production_host_cause") == "OPEN_PENDING_PART4_PROBE"
        and correction.get("design_depends_on_specific_cause") is False
        and correction.get("retracted_hypotheses")
        == ["pinned_memory_deregistration", "unlink_writeback_during_open"]
        and isinstance(candidates, list)
        and candidates
    ):
        return False

    any_obstruction = False
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        boundaries = candidate.get("boundaries")
        obstruction_reasons = candidate.get("obstruction_reasons")
        controls = candidate.get("zero_expected_controls")
        if not (
            _x4c_nonnegative_int(candidate.get("ordinal"))
            and isinstance(candidate.get("accepted"), bool)
            and isinstance(obstruction_reasons, list)
            and all(
                isinstance(reason, str) and reason for reason in obstruction_reasons
            )
            and _x4c_boundary_timeline_valid(
                boundaries, require_available=False
            )
            and _x4c_lifecycle_timeline_valid(
                candidate.get("events"), candidate.get("spans"), boundaries
            )
            and candidate.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
            and candidate.get("pcs_bytes") == X4_V4_PCS_BYTES
            and candidate.get("response_bytes") == X4_V4_RESPONSE_BYTES
            and isinstance(controls, dict)
            and all(
                _x4c_nonnegative_int(controls.get(key))
                for key in (
                    "pinned_memory_deregistrations_during_open",
                    "unlink_calls_during_open",
                    "writeback_bytes_during_open",
                    "sealed_owned_pinned_bytes",
                    "sealed_owned_device_bytes",
                    "sealed_owned_file_backed_bytes",
                )
            )
        ):
            return False
        control_keys = (
            "pinned_memory_deregistrations_during_open",
            "unlink_calls_during_open",
            "writeback_bytes_during_open",
            "sealed_owned_pinned_bytes",
            "sealed_owned_device_bytes",
            "sealed_owned_file_backed_bytes",
        )
        nonzero_control = any(controls[key] != 0 for key in control_keys)
        missing_counter = any(
            not boundary[group]["availability"]["available"]
            for boundary in boundaries
            for group in (
                "process_io",
                "page_faults",
                "process_memory",
                "smaps_rollup",
                "allocator",
                "numa",
                "cuda",
            )
        )
        candidate_obstruction = bool(obstruction_reasons)
        if (nonzero_control or missing_counter) != candidate_obstruction or candidate[
            "accepted"
        ] is candidate_obstruction:
            return False
        any_obstruction |= candidate_obstruction

        maximum = {
            "pinned": max(
                boundary["sealed_ownership"]["pinned_host_bytes"]
                for boundary in boundaries
            ),
            "device": max(
                boundary["sealed_ownership"]["device_bytes"]
                for boundary in boundaries
            ),
            "file": max(
                boundary["sealed_ownership"]["file_backed_bytes"]
                for boundary in boundaries
            ),
        }
        if (
            controls["sealed_owned_pinned_bytes"] != maximum["pinned"]
            or controls["sealed_owned_device_bytes"] != maximum["device"]
            or controls["sealed_owned_file_backed_bytes"] != maximum["file"]
        ):
            return False
        opening_boundaries = [
            boundaries[event["boundary_seq"]]
            for event in candidate["events"]
            if event["track"] == "legacy_opening"
        ]
        if not opening_boundaries:
            return False
        opening_boundaries.sort(key=lambda boundary: boundary["seq"])
        if any(
            boundary["sealed_ownership"]["owned_file_count"] != 0
            or boundary["sealed_ownership"]["owned_mapping_count"] != 0
            or boundary["sealed_ownership"]["borrowed_initial_source_file_count"] != 5
            for boundary in opening_boundaries
        ) and not candidate_obstruction:
            return False
        initial_ownership = opening_boundaries[0]["sealed_ownership"]
        if (
            initial_ownership["fold_codeword_bytes"]
            != X4C_PRODUCTION_FOLD_CODEWORD_BYTES
            or initial_ownership["fold_outer_cache_bytes"]
            != X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
            or initial_ownership["ordinary_host_bytes"]
            != X4C_PRODUCTION_SEALED_STATE_BYTES
        ):
            return False
        phase_end_boundaries = {
            event["phase"]: boundaries[event["boundary_seq"]]
            for event in candidate["events"]
            if event["track"] == "legacy_opening"
            and event["transition"] == "span_end"
            and event["phase"]
            in {
                "destroy_codewords",
                "destroy_outer_cache_levels",
                "destroy_remaining_sealed_state",
            }
        }
        after_codewords = phase_end_boundaries.get("destroy_codewords", {}).get(
            "sealed_ownership", {}
        )
        after_cache = phase_end_boundaries.get("destroy_outer_cache_levels", {}).get(
            "sealed_ownership", {}
        )
        after_remaining = phase_end_boundaries.get(
            "destroy_remaining_sealed_state", {}
        ).get("sealed_ownership", {})
        if not (
            after_codewords.get("fold_codeword_bytes") == 0
            and after_codewords.get("fold_outer_cache_bytes")
            == X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
            and after_codewords.get("ordinary_host_bytes")
            == X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
            and after_cache.get("fold_codeword_bytes") == 0
            and after_cache.get("fold_outer_cache_bytes") == 0
            and after_cache.get("ordinary_host_bytes") == 0
            and after_remaining.get("ordinary_host_bytes") == 0
        ):
            return False
        opening_unlinks = (
            opening_boundaries[-1]["temporary_files"]["cumulative_deleted_files"]
            - opening_boundaries[0]["temporary_files"]["cumulative_deleted_files"]
        )
        if controls["unlink_calls_during_open"] != opening_unlinks:
            return False

    verdict = row.get("verdict")
    return (
        isinstance(verdict, str)
        and (
            (not any_obstruction and verdict.startswith("DIAGNOSTIC_COMPLETE"))
            or (any_obstruction and verdict.startswith("HARD_STOP_OBSTRUCTION"))
        )
        and row.get("hard_stop") is any_obstruction
    )


def validate_x4c_legacy_causal_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4c_legacy_causal_result_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4c_has(row: Any, keys: tuple[str, ...]) -> bool:
    return isinstance(row, dict) and all(key in row for key in keys)


def _x4c_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _x4c_pin_valid(row: Any) -> bool:
    return (
        _x4c_has(row, ("path", "sha256", "git_sha"))
        and isinstance(row["path"], str)
        and bool(row["path"])
        and _x4c_hex(row["sha256"], 64)
        and _x4c_hex(row["git_sha"], 40)
    )


def _x4c_v1_machine_valid(row: Any) -> bool:
    return (
        _x4c_has(
            row,
            (
                "provider",
                "pod_id",
                "gpu",
                "gpu_uuid",
                "cuda_visible_devices",
                "host_ram_bytes",
                "logical_cpus",
                "rayon_workers",
                "commit_seal_open_unpinned",
                "persistent_root",
                "persistent_filesystem_type",
                "persistent_available_bytes",
                "local_root",
                "local_filesystem_type",
                "local_available_bytes",
            ),
        )
        and row["provider"] == "RunPod"
        and row["gpu"] == "NVIDIA A100-SXM4-80GB"
        and isinstance(row["pod_id"], str)
        and bool(row["pod_id"])
        and isinstance(row["gpu_uuid"], str)
        and row["gpu_uuid"].startswith("GPU-")
        and isinstance(row["cuda_visible_devices"], str)
        and bool(row["cuda_visible_devices"])
        and _x4c_positive_int(row["logical_cpus"])
        and row["rayon_workers"] == row["logical_cpus"]
        and row["host_ram_bytes"] >= X4C_MIN_HOST_RAM_BYTES
        and row["local_available_bytes"] >= X4C_MIN_LOCAL_STORAGE_BYTES
        and _x4c_nonnegative_int(row["persistent_available_bytes"])
        and row["commit_seal_open_unpinned"] is True
        and row["persistent_filesystem_type"] != "mfs"
        and row["local_filesystem_type"] != "mfs"
    )


_X4C_IO_KEYS = (
    "rchar",
    "wchar",
    "syscr",
    "syscw",
    "read_bytes",
    "write_bytes",
    "cancelled_write_bytes",
    "observer_rchar_bytes",
    "unexpected_rchar_bytes",
    "unexpected_wchar_bytes",
    "unexpected_read_bytes",
    "unexpected_write_bytes",
    "response_window_exact",
)


def _x4c_io_valid(row: Any, *, response: bool) -> bool:
    if not (
        _x4c_has(row, _X4C_IO_KEYS)
        and all(_x4c_nonnegative_int(row[key]) for key in _X4C_IO_KEYS[:-1])
        and isinstance(row["response_window_exact"], bool)
    ):
        return False
    if not response:
        return True
    return (
        row["response_window_exact"] is True
        and row["rchar"] == row["observer_rchar_bytes"]
        and row["wchar"] == 0
        and row["read_bytes"] == 0
        and row["write_bytes"] == 0
        and row["cancelled_write_bytes"] == 0
        and all(
            row[key] == 0
            for key in (
                "unexpected_rchar_bytes",
                "unexpected_wchar_bytes",
                "unexpected_read_bytes",
                "unexpected_write_bytes",
            )
        )
    )


_X4C_BACKEND_INT_KEYS = (
    "measurement_wall_ns",
    "unattributed_cpu_residual_ns",
    "h2d_bytes",
    "d2h_bytes",
    "explicit_d2d_copy_bytes",
    "device_zeroed_bytes",
    "device_generated_bytes",
    "resident_h2d_host_calls",
    "resident_d2h_host_calls",
    "synchronizations",
    "sync_host_output",
    "sync_upload_lifetime",
    "sync_timing_flush",
    "sync_profiling_legacy",
    "sync_allocator_flush",
    "allocation_calls",
    "resident_alloc_requests",
    "resident_reuse_hits",
    "resident_free_requests",
    "physical_free_calls",
    "live_device_bytes",
    "peak_device_bytes",
    "pinned_allocation_calls",
    "pinned_alloc_requests",
    "pinned_reuse_hits",
    "pinned_free_requests",
    "pinned_physical_free_calls",
    "pinned_host_write_calls",
    "pinned_host_write_bytes",
    "live_pinned_bytes",
    "peak_pinned_bytes",
    "x4c_arena_reset_calls",
    "x4c_arena_reset_bytes",
    "x4c_kernel_launches",
    "x4c_control_peek_calls",
    "x4c_control_peek_pending",
    "timing_records",
    "timing_elapsed_query_attempts",
    "timing_elapsed_no_write",
    "timing_event_queries",
    "timing_event_api_calls",
    "timing_pending_high_water",
    "timing_flush_count",
    "coarse_timing_scopes",
)


def _x4c_backend_valid(row: Any) -> bool:
    if not (
        _x4c_has(
            row,
            _X4C_BACKEND_INT_KEYS
            + (
                "operations",
                "operation_kernel_ns",
                "operation_cpu_residual_ns",
            ),
        )
        and all(_x4c_nonnegative_int(row[key]) for key in _X4C_BACKEND_INT_KEYS)
    ):
        return False
    expected_names = (
        "gemm",
        "logup",
        "pcs_rows",
        "pcs_ntt",
        "pcs_merkle",
        "auth_masks",
        "mailbox",
    )
    for key in ("operations", "operation_kernel_ns", "operation_cpu_residual_ns"):
        values = row[key]
        if not (
            isinstance(values, list)
            and len(values) == len(expected_names)
            and tuple(item[0] for item in values) == expected_names
            and all(
                isinstance(item, list)
                and len(item) == 2
                and _x4c_nonnegative_int(item[1])
                for item in values
            )
        ):
            return False
    return all(
        row[key] == 0
        for key in (
            "timing_records",
            "timing_elapsed_query_attempts",
            "timing_elapsed_no_write",
            "timing_event_queries",
            "timing_event_api_calls",
            "timing_pending_high_water",
            "timing_flush_count",
            "coarse_timing_scopes",
        )
    )


def _x4c_durable_census_valid(row: Any) -> bool:
    keys = (
        "cohort_directory_count",
        "cohort_ids",
        "coefficient_file_count",
        "root_file_count",
        "oracle_file_count",
        "other_file_count",
        "other_directory_count",
        "symlink_count",
        "total_regular_file_bytes",
        "unexpected_paths",
        "exact",
    )
    expected_ids = [cohort[0] for cohort in X4C_COHORTS]
    return (
        _x4c_has(row, keys)
        and row["cohort_directory_count"] == 5
        and row["cohort_ids"] == expected_ids
        and row["coefficient_file_count"] == 5
        and row["root_file_count"] == 5
        and row["oracle_file_count"] == 0
        and row["other_file_count"] == 0
        and row["other_directory_count"] == 0
        and row["symlink_count"] == 0
        and row["total_regular_file_bytes"] == X4C_DURABLE_BYTES
        and row["unexpected_paths"] == []
        and row["exact"] is True
    )


def _x4c_onboarding_pass_valid(
    row: Any,
    *,
    role: str,
    measured: bool,
    retained: bool,
) -> bool:
    if not (
        _x4c_has(
            row,
            (
                "role",
                "measured",
                "wall_s",
                "io",
                "backend",
                "cohorts",
                "coefficient_bytes",
                "oracle_bytes",
                "root_bytes",
                "retained_durable",
                "cleanup_complete",
                "accepted",
            ),
        )
        and row["role"] == role
        and row["measured"] is measured
        and isinstance(row["wall_s"], (int, float))
        and not isinstance(row["wall_s"], bool)
        and row["wall_s"] > 0
        and _x4c_io_valid(row["io"], response=False)
        and _x4c_backend_valid(row["backend"])
        and row["coefficient_bytes"] == X4C_DURABLE_COEFFICIENT_BYTES
        and row["oracle_bytes"] == X4C_INITIAL_ORACLE_BYTES
        and row["root_bytes"] == X4C_DURABLE_ROOT_BYTES
        and row["retained_durable"] is retained
        and row["cleanup_complete"] is True
        and row["accepted"] is True
        and isinstance(row["cohorts"], list)
        and len(row["cohorts"]) == 5
    ):
        return False
    coefficient_sum = oracle_sum = root_sum = h2d_sum = d2h_sum = 0
    for cohort, expected in zip(row["cohorts"], X4C_COHORTS, strict=True):
        cohort_id, coefficient_bytes, _ = expected
        metrics = cohort.get("metrics") if isinstance(cohort, dict) else None
        if not (
            _x4c_has(cohort, ("cohort_id", "root_hex", "metrics"))
            and cohort["cohort_id"] == cohort_id
            and _x4c_hex(cohort["root_hex"], 64)
            and _x4c_has(
                metrics,
                (
                    "coefficient_bytes_persisted",
                    "oracle_bytes_persisted",
                    "root_bytes_persisted",
                    "staging_bytes_read",
                    "staging_bytes_written",
                    "retained_outer_cache_bytes",
                    "expected_h2d_bytes",
                    "expected_d2h_bytes",
                ),
            )
            and all(
                _x4c_nonnegative_int(metrics[key])
                for key in (
                    "coefficient_bytes_persisted",
                    "oracle_bytes_persisted",
                    "root_bytes_persisted",
                    "staging_bytes_read",
                    "staging_bytes_written",
                    "retained_outer_cache_bytes",
                    "expected_h2d_bytes",
                    "expected_d2h_bytes",
                )
            )
            and metrics["coefficient_bytes_persisted"] == coefficient_bytes
            and metrics["oracle_bytes_persisted"] == coefficient_bytes * 8
            and metrics["root_bytes_persisted"] == 32
        ):
            return False
        coefficient_sum += metrics["coefficient_bytes_persisted"]
        oracle_sum += metrics["oracle_bytes_persisted"]
        root_sum += metrics["root_bytes_persisted"]
        h2d_sum += metrics["expected_h2d_bytes"]
        d2h_sum += metrics["expected_d2h_bytes"]
    return (
        coefficient_sum == row["coefficient_bytes"]
        and oracle_sum == row["oracle_bytes"]
        and root_sum == row["root_bytes"]
        and row["backend"]["h2d_bytes"] == h2d_sum
        and row["backend"]["d2h_bytes"] == d2h_sum
    )


def _x4c_onboarding_result_valid(row: Any) -> bool:
    required = (
        "schema",
        "milestone",
        "git_sha",
        "git_dirty",
        "pod_profile",
        "protocol_profile",
        "design_sha256",
        "clean_source_sha256",
        "note6",
        "lifecycle_probe",
        "machine",
        "warmup",
        "measured",
        "selected_upper_median_wall_s",
        "durable_files",
        "durable_census",
        "durable_coefficient_file_count",
        "durable_root_file_count",
        "durable_oracle_file_count",
        "durable_bytes",
        "durable_tier_exact",
        "roots_identical_across_passes",
        "response_work_executed",
        "complete_online_wall_ceiling",
        "overall_pass",
    )
    if not (
        _x4c_has(row, required)
        and row["schema"] == 2
        and row["milestone"] == X4C_ONBOARDING_MILESTONE
        and _x4c_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["pod_profile"] == X4C_POD_PROFILE
        and row["protocol_profile"] == X4_V4_PROFILE
        and row["design_sha256"] == X4C_V1_DESIGN_SHA256
        and _x4c_hex(row["clean_source_sha256"], 64)
        and _x4c_pin_valid(row["note6"])
        and _x4c_pin_valid(row["lifecycle_probe"])
        and _x4c_v1_machine_valid(row["machine"])
        and _x4c_onboarding_pass_valid(
            row["warmup"], role="warmup", measured=False, retained=False
        )
        and isinstance(row["measured"], list)
        and len(row["measured"]) == 3
        and all(
            _x4c_onboarding_pass_valid(
                candidate,
                role=f"measured-{ordinal}",
                measured=True,
                retained=ordinal == 3,
            )
            for ordinal, candidate in enumerate(row["measured"], 1)
        )
        and _x4c_durable_census_valid(row["durable_census"])
        and row["durable_coefficient_file_count"] == 5
        and row["durable_root_file_count"] == 5
        and row["durable_oracle_file_count"] == 0
        and row["durable_bytes"] == X4C_DURABLE_BYTES
        and row["durable_tier_exact"] is True
        and row["roots_identical_across_passes"] is True
        and row["response_work_executed"] is False
        and row["complete_online_wall_ceiling"] is None
        and row["overall_pass"] is True
        and isinstance(row["durable_files"], list)
        and len(row["durable_files"]) == 5
    ):
        return False
    measured_walls = [candidate["wall_s"] for candidate in row["measured"]]
    if row["selected_upper_median_wall_s"] != sorted(measured_walls)[1]:
        return False
    roots = [cohort["root_hex"] for cohort in row["warmup"]["cohorts"]]
    for candidate in row["measured"]:
        if [cohort["root_hex"] for cohort in candidate["cohorts"]] != roots:
            return False
    for durable, expected, root in zip(
        row["durable_files"], X4C_COHORTS, roots, strict=True
    ):
        cohort_id, coefficient_bytes, _ = expected
        if not (
            _x4c_has(
                durable,
                (
                    "cohort_id",
                    "coefficient_path",
                    "coefficient_bytes",
                    "coefficient_sha256",
                    "root_path",
                    "root_bytes",
                    "root_hex",
                    "root_sha256",
                ),
            )
            and durable["cohort_id"] == cohort_id
            and durable["coefficient_bytes"] == coefficient_bytes
            and durable["root_bytes"] == 32
            and durable["root_hex"] == root
            and _x4c_hex(durable["coefficient_sha256"], 64)
            and _x4c_hex(durable["root_sha256"], 64)
            and Path(durable["coefficient_path"]).name == "coefficients.bin"
            and Path(durable["root_path"]).name == "root.bin"
        ):
            return False
    return True


def validate_x4c_onboarding_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4c_onboarding_result_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


_X4C_ARENA_INT_KEYS = (
    "capacity_bytes",
    "committed_bytes",
    "peak_bytes",
    "logical_allocations",
    "response_round_allocations",
    "reallocations",
    "logical_deallocations",
    "reset_count",
    "zeroed_bytes",
    "outstanding_allocations",
    "outstanding_bytes",
    "cached_reusable_bytes",
    "backend_workspace_bytes",
    "backend_baseline_resident_bytes",
    "backend_resident_bytes",
    "backend_cached_resident_bytes",
    "baseline_active_device_allocations",
    "active_device_allocations",
    "cached_device_allocations",
    "baseline_active_pinned_allocations",
    "baseline_active_pinned_bytes",
    "active_pinned_allocations",
    "cached_pinned_allocations",
    "in_flight_pinned_allocations",
    "active_pinned_bytes",
    "cached_pinned_bytes",
    "outstanding_cuda_operations",
    "pinned_pool_allocations",
    "pinned_pool_requested_bytes",
    "native_live_device_bytes",
    "native_peak_device_bytes",
    "native_resident_alloc_requests",
    "native_resident_reuse_hits",
    "native_resident_free_requests",
    "native_arena_reset_calls",
    "native_arena_reset_bytes",
    "native_device_zeroed_bytes",
)


def _x4c_arena_valid(row: Any, *, proof_ready: bool) -> bool:
    if not (
        _x4c_has(row, _X4C_ARENA_INT_KEYS + ("accelerator_available", "stream_synchronized"))
        and all(_x4c_nonnegative_int(row[key]) for key in _X4C_ARENA_INT_KEYS)
        and row["accelerator_available"] is True
        and row["stream_synchronized"] is True
        and row["capacity_bytes"] == X4C_ARENA_BYTES
        and row["committed_bytes"] == X4C_ARENA_BYTES
        and row["peak_bytes"] == row["native_peak_device_bytes"]
        and row["peak_bytes"] >= X4C_ARENA_BYTES
        and row["logical_allocations"] == row["native_resident_alloc_requests"] == 1
        and row["response_round_allocations"] == 0
        and row["reallocations"] == 0
        and row["logical_deallocations"] == row["native_resident_free_requests"]
        and row["reset_count"] == row["native_arena_reset_calls"]
        and row["zeroed_bytes"] == row["native_device_zeroed_bytes"]
        and row["outstanding_cuda_operations"] == 0
        and row["in_flight_pinned_allocations"] == 0
        and row["pinned_pool_allocations"] == 4
        and row["pinned_pool_requested_bytes"] == 1_090_741_982
        and row["active_pinned_allocations"]
        == row["baseline_active_pinned_allocations"] + 4
        and row["active_pinned_bytes"]
        >= row["baseline_active_pinned_bytes"] + row["pinned_pool_requested_bytes"]
    ):
        return False
    if proof_ready:
        return (
            row["logical_deallocations"] == 0
            and row["reset_count"] == 0
            and row["zeroed_bytes"] == 0
            and row["native_arena_reset_bytes"] == 0
            and row["outstanding_allocations"] == 1
            and row["outstanding_bytes"] == X4C_ARENA_BYTES
            and row["cached_reusable_bytes"] == 0
            and row["active_device_allocations"]
            == row["baseline_active_device_allocations"] + 1
        )
    return (
        row["logical_deallocations"] == 1
        and row["reset_count"] == 1
        and row["zeroed_bytes"] == X4C_ARENA_BYTES
        and row["native_arena_reset_bytes"] == X4C_ARENA_BYTES
        and row["outstanding_allocations"] == 0
        and row["outstanding_bytes"] == 0
        and row["cached_reusable_bytes"] == X4C_ARENA_BYTES
        and row["active_device_allocations"] == row["baseline_active_device_allocations"]
    )


def _x4c_response_candidate_valid(
    row: Any, *, role: str, ordinal: int, measured: bool
) -> bool:
    if not (
        _x4c_has(
            row,
            (
                "role",
                "measured",
                "ordinal",
                "epoch",
                "seal_wall_s",
                "open_wall_s",
                "verify_wall_s",
                "proof_ready_wall_s",
                "session_reusable_wall_s",
                "complete_online_wall_s",
                "global_folding_proof_bytes",
                "complete_pcs_bytes",
                "frozen_non_query_pcs_bytes",
                "packed_opening_bytes",
                "packed_opened_symbol_count",
                "packed_opened_symbol_bytes",
                "packed_initial_inner_sibling_count",
                "packed_initial_inner_sibling_bytes",
                "packed_initial_outer_sibling_count",
                "packed_initial_outer_sibling_bytes",
                "packed_fold_outer_sibling_count",
                "packed_fold_outer_sibling_bytes",
                "packed_metadata_bytes",
                "packed_components_exact",
                "selected_query_tape_blake3",
                "selected_query_tape_exact",
                "fold_challenges_replayed",
                "response_bytes",
                "query_draws",
                "verifier_accepted",
                "transcript_bytes_equal",
                "transcript_ledger_equal",
                "process_io",
                "response_window_io_exact",
                "backend",
                "metrics",
                "expected_h2d_bytes",
                "expected_d2h_bytes",
                "traffic_exact",
                "zero_response_staging",
                "accepted",
            ),
        )
        and row["role"] == role
        and row["ordinal"] == ordinal
        and row["measured"] is measured
        and row["epoch"] == 0x58430000 + ordinal
        and all(
            isinstance(row[key], (int, float))
            and not isinstance(row[key], bool)
            and row[key] > 0
            for key in (
                "seal_wall_s",
                "open_wall_s",
                "verify_wall_s",
                "proof_ready_wall_s",
                "session_reusable_wall_s",
                "complete_online_wall_s",
            )
        )
        and row["session_reusable_wall_s"] >= row["proof_ready_wall_s"]
        and row["global_folding_proof_bytes"] == X4C_GLOBAL_FOLDING_PROOF_BYTES
        and row["complete_pcs_bytes"] == X4_V4_PCS_BYTES
        and row["frozen_non_query_pcs_bytes"] == X4C_MANDATORY_NON_QUERY_BYTES
        and row["packed_opening_bytes"] == X4C_PACKED_OPENING_BYTES
        and row["response_bytes"] == X4_V4_RESPONSE_BYTES
        and row["query_draws"] == 111
        and row["packed_opened_symbol_bytes"] == row["packed_opened_symbol_count"] * 16
        and row["packed_initial_inner_sibling_bytes"]
        == row["packed_initial_inner_sibling_count"] * 32
        and row["packed_initial_outer_sibling_bytes"]
        == row["packed_initial_outer_sibling_count"] * 32
        and row["packed_fold_outer_sibling_bytes"]
        == row["packed_fold_outer_sibling_count"] * 32
        and sum(
            row[key]
            for key in (
                "packed_opened_symbol_bytes",
                "packed_initial_inner_sibling_bytes",
                "packed_initial_outer_sibling_bytes",
                "packed_fold_outer_sibling_bytes",
                "packed_metadata_bytes",
            )
        )
        == X4C_PACKED_OPENING_BYTES
        and row["packed_components_exact"] is True
        and _x4c_hex(row["selected_query_tape_blake3"], 64)
        and row["selected_query_tape_exact"] is True
        and row["fold_challenges_replayed"] is True
        and row["verifier_accepted"] is True
        and row["transcript_bytes_equal"] is True
        and row["transcript_ledger_equal"] is True
        and _x4c_io_valid(row["process_io"], response=True)
        and row["response_window_io_exact"] is True
        and _x4c_backend_valid(row["backend"])
        and row["traffic_exact"] is True
        and row["zero_response_staging"] is True
        and row["accepted"] is True
    ):
        return False
    metrics = row["metrics"]
    if not _x4c_has(
        metrics,
        (
            "response_io",
            "execution",
            "proof_ready_arena",
            "session_reusable_arena",
            "proof_ready_wall_ns",
            "session_reusable_wall_ns",
            "source_coefficients_read",
            "initial_encoded_symbols_read",
            "combined_codeword_symbols",
            "serialized_fold_bytes",
            "serialized_packed_opening_bytes",
            "sampling_soundness_credit_bits",
        ),
    ):
        return False
    response_io = metrics["response_io"]
    if not (
        isinstance(response_io, dict)
        and len(response_io) == 9
        and all(_x4c_nonnegative_int(value) and value == 0 for value in response_io.values())
    ):
        return False
    execution = metrics["execution"]
    expected_execution = {
        "direct_fold_calls": 27,
        "diagnostic_comparisons": 1_592,
        "diagnostic_mismatches": 0,
        "diagnostic_gather_calls": 53,
        "diagnostic_index_h2d_bytes": 37_184,
        "diagnostic_value_d2h_bytes": 74_368,
        "n4_tree_calls": 27,
        "query_gather_calls": 1,
        "query_gather_operation_count": 53_898,
        "query_gather_operation_h2d_bytes": 4_743_024,
        "canonical_template_h2d_bytes": X4C_PACKED_OPENING_BYTES,
        "query_draw_count": 111,
        "canonical_opening_d2h_bytes": X4C_PACKED_OPENING_BYTES,
        "noncanonical_opening_d2h_bytes": 0,
        "cpu_fold_tree_clone_bytes": 0,
    }
    if not isinstance(execution, dict) or any(
        execution.get(key) != value for key, value in expected_execution.items()
    ):
        return False
    expected_h2d = (
        metrics["combined_codeword_symbols"] * 16
        + execution["diagnostic_index_h2d_bytes"]
        + execution["query_gather_operation_h2d_bytes"]
        + execution["canonical_template_h2d_bytes"]
    )
    expected_d2h = (
        27 * 32
        + execution["diagnostic_value_d2h_bytes"]
        + execution["canonical_opening_d2h_bytes"]
    )
    backend = row["backend"]
    return (
        metrics["source_coefficients_read"] == 601_161_728
        and metrics["initial_encoded_symbols_read"] == 4_809_293_824
        and metrics["combined_codeword_symbols"] == 1_159_200_768
        and metrics["serialized_fold_bytes"] == 2_446
        and metrics["serialized_packed_opening_bytes"] == X4C_PACKED_OPENING_BYTES
        and metrics["sampling_soundness_credit_bits"] == 0
        and metrics["proof_ready_wall_ns"] > 0
        and metrics["session_reusable_wall_ns"] >= metrics["proof_ready_wall_ns"]
        and _x4c_arena_valid(metrics["proof_ready_arena"], proof_ready=True)
        and _x4c_arena_valid(metrics["session_reusable_arena"], proof_ready=False)
        and row["expected_h2d_bytes"] == expected_h2d == backend["h2d_bytes"]
        and row["expected_d2h_bytes"] == expected_d2h == backend["d2h_bytes"]
        and backend["explicit_d2d_copy_bytes"] == 0
        and backend["device_generated_bytes"] == 0
        and backend["resident_alloc_requests"] == 1
        and backend["resident_free_requests"] == 1
        and backend["x4c_arena_reset_calls"] == 1
        and backend["x4c_arena_reset_bytes"] == X4C_ARENA_BYTES
        and backend["device_zeroed_bytes"] == X4C_ARENA_BYTES
        and all(
            backend[key] == 0
            for key in (
                "pinned_allocation_calls",
                "pinned_alloc_requests",
                "pinned_reuse_hits",
                "pinned_free_requests",
                "pinned_physical_free_calls",
            )
        )
    )


def _x4c_rebuild_valid(row: Any, onboarding: dict[str, Any]) -> bool:
    if not (
        _x4c_has(
            row,
            (
                "wall_s",
                "io",
                "parallel_task_count",
                "rayon_workers",
                "cohorts",
                "coefficient_bytes_read",
                "host_oracle_bytes",
                "host_outer_cache_bytes",
                "roots",
                "roots_equal_onboarding",
                "durable_oracle_files",
                "durable_census_before",
                "durable_census_after",
                "durable_census_stable",
                "accepted",
            ),
        )
        and isinstance(row["wall_s"], (int, float))
        and row["wall_s"] > 0
        and _x4c_io_valid(row["io"], response=False)
        and row["parallel_task_count"] == 5
        and _x4c_positive_int(row["rayon_workers"])
        and row["coefficient_bytes_read"] == X4C_DURABLE_COEFFICIENT_BYTES
        and row["host_oracle_bytes"] == X4C_INITIAL_ORACLE_BYTES
        and row["host_outer_cache_bytes"] == X4C_INITIAL_OUTER_CACHE_BYTES
        and row["durable_oracle_files"] == 0
        and _x4c_durable_census_valid(row["durable_census_before"])
        and _x4c_durable_census_valid(row["durable_census_after"])
        and row["durable_census_before"] == row["durable_census_after"]
        and row["durable_census_stable"] is True
        and row["roots_equal_onboarding"] is True
        and row["accepted"] is True
        and isinstance(row["cohorts"], list)
        and len(row["cohorts"]) == 5
    ):
        return False
    expected_roots = [item["root_hex"] for item in onboarding["durable_files"]]
    if row["roots"] != expected_roots:
        return False
    for ordinal, (cohort, expected, root) in enumerate(
        zip(row["cohorts"], X4C_COHORTS, expected_roots, strict=True)
    ):
        cohort_id, coefficient_bytes, cache_bytes = expected
        if not (
            _x4c_has(
                cohort,
                (
                    "ordinal",
                    "cohort_id",
                    "coefficient_bytes_read",
                    "host_oracle_bytes",
                    "host_outer_cache_bytes",
                    "root",
                    "expected_root",
                    "root_equal",
                    "durable_oracle_file",
                    "accepted",
                ),
            )
            and cohort["ordinal"] == ordinal
            and cohort["cohort_id"] == cohort_id
            and cohort["coefficient_bytes_read"] == coefficient_bytes
            and cohort["host_oracle_bytes"] == coefficient_bytes * 8
            and cohort["host_outer_cache_bytes"] == cache_bytes
            and cohort["root"] == cohort["expected_root"] == root
            and cohort["root_equal"] is True
            and cohort["durable_oracle_file"] is False
            and cohort["accepted"] is True
        ):
            return False
    return True


def _x4c_online_result_valid(
    row: Any,
    onboarding: dict[str, Any],
    onboarding_sha256: str,
) -> bool:
    if not (
        _x4c_onboarding_result_valid(onboarding)
        and _x4c_has(
            row,
            (
                "schema",
                "milestone",
                "git_sha",
                "git_dirty",
                "pod_profile",
                "protocol_profile",
                "design_sha256",
                "clean_source_sha256",
                "note6",
                "lifecycle_probe",
                "onboarding",
                "expected_onboarding_sha256",
                "onboarding_sha256_exact",
                "machine",
                "fresh_process_rebuild",
                "warmup",
                "measured",
                "selected_upper_median_open_wall_s",
                "selected_upper_median_verify_wall_s",
                "selected_upper_median_proof_ready_wall_s",
                "selected_upper_median_session_reusable_wall_s",
                "selected_upper_median_complete_online_wall_s",
                "open_ceiling_s",
                "verify_ceiling_s",
                "open_pass",
                "verify_pass",
                "all_candidates_accepted",
                "zero_response_staging",
                "exact_communication",
                "diagnostic_comparisons",
                "diagnostic_soundness_credit_bits",
                "pinned_pool_release_wall_s",
                "pinned_pool_release_restored_ownership",
                "protocol_or_parameter_change",
                "root_or_proof_format_change",
                "lean_or_soundness_change",
                "overall_pass",
            ),
        )
        and row["schema"] == 2
        and row["milestone"] == X4C_ONLINE_MILESTONE
        and row["git_sha"] == onboarding["git_sha"]
        and row["git_dirty"] is False
        and row["pod_profile"] == X4C_POD_PROFILE
        and row["protocol_profile"] == X4_V4_PROFILE
        and row["design_sha256"] == X4C_V1_DESIGN_SHA256
        and row["clean_source_sha256"] == onboarding["clean_source_sha256"]
        and _x4c_pin_valid(row["note6"])
        and _x4c_pin_valid(row["lifecycle_probe"])
        and _x4c_pin_valid(row["onboarding"])
        and row["onboarding"]["sha256"] == onboarding_sha256
        and row["onboarding"]["git_sha"] == onboarding["git_sha"]
        and row["expected_onboarding_sha256"] == onboarding_sha256
        and row["onboarding_sha256_exact"] is True
        and _x4c_v1_machine_valid(row["machine"])
        and row["machine"]["pod_id"] == onboarding["machine"]["pod_id"]
        and row["machine"]["gpu_uuid"] == onboarding["machine"]["gpu_uuid"]
        and _x4c_rebuild_valid(row["fresh_process_rebuild"], onboarding)
        and _x4c_response_candidate_valid(
            row["warmup"], role="warmup", ordinal=0, measured=False
        )
        and isinstance(row["measured"], list)
        and len(row["measured"]) == 3
        and all(
            _x4c_response_candidate_valid(
                candidate,
                role=f"measured-{ordinal}",
                ordinal=ordinal,
                measured=True,
            )
            for ordinal, candidate in enumerate(row["measured"], 1)
        )
    ):
        return False
    medians = {
        "selected_upper_median_open_wall_s": "open_wall_s",
        "selected_upper_median_verify_wall_s": "verify_wall_s",
        "selected_upper_median_proof_ready_wall_s": "proof_ready_wall_s",
        "selected_upper_median_session_reusable_wall_s": "session_reusable_wall_s",
        "selected_upper_median_complete_online_wall_s": "complete_online_wall_s",
    }
    if any(
        row[output] != sorted(candidate[source] for candidate in row["measured"])[1]
        for output, source in medians.items()
    ):
        return False
    candidates = [row["warmup"], *row["measured"]]
    open_pass = row["selected_upper_median_open_wall_s"] <= row["open_ceiling_s"]
    verify_pass = (
        row["selected_upper_median_verify_wall_s"] <= row["verify_ceiling_s"]
    )
    return (
        row["open_ceiling_s"] == 1.50
        and row["verify_ceiling_s"] == 0.25
        and row["open_pass"] is open_pass is True
        and row["verify_pass"] is verify_pass is True
        and row["all_candidates_accepted"] is all(
            candidate["accepted"] for candidate in candidates
        )
        and row["all_candidates_accepted"] is True
        and row["zero_response_staging"] is all(
            candidate["zero_response_staging"] for candidate in candidates
        )
        and row["zero_response_staging"] is True
        and row["exact_communication"] is all(
            candidate["complete_pcs_bytes"] == X4_V4_PCS_BYTES
            and candidate["response_bytes"] == X4_V4_RESPONSE_BYTES
            for candidate in candidates
        )
        and row["exact_communication"] is True
        and row["diagnostic_comparisons"] == 1_592
        and row["diagnostic_soundness_credit_bits"] == 0
        and isinstance(row["pinned_pool_release_wall_s"], (int, float))
        and row["pinned_pool_release_wall_s"] >= 0
        and row["pinned_pool_release_restored_ownership"] is True
        and row["protocol_or_parameter_change"] is False
        and row["root_or_proof_format_change"] is False
        and row["lean_or_soundness_change"] is False
        and row["overall_pass"] is True
    )


def validate_x4c_online_result(path: Path, onboarding_path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        if not onboarding_path.is_absolute():
            onboarding_path = REPO / onboarding_path
        with path.open("r", encoding="utf-8") as handle:
            online = json.load(handle)
        onboarding_bytes = onboarding_path.read_bytes()
        onboarding = json.loads(onboarding_bytes)
        onboarding_sha256 = hashlib.sha256(onboarding_bytes).hexdigest()
        return _x4c_online_result_valid(online, onboarding, onboarding_sha256)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4c_gpt2_backend_valid(row: Any) -> bool:
    integer_keys = (
        "measurement_wall_ns",
        "h2d_bytes",
        "d2h_bytes",
        "explicit_d2d_copy_bytes",
        "device_zeroed_bytes",
        "device_generated_bytes",
        "resident_alloc_requests",
        "resident_reuse_hits",
        "resident_free_requests",
        "live_device_bytes",
        "peak_device_bytes",
        "pinned_allocation_calls",
        "pinned_alloc_requests",
        "pinned_reuse_hits",
        "pinned_free_requests",
        "pinned_physical_free_calls",
        "live_pinned_bytes",
        "peak_pinned_bytes",
        "x4c_arena_reset_calls",
        "x4c_arena_reset_bytes",
        "timing_event_api_calls",
        "outstanding_timing_records",
    )
    expected_operations = (
        "gemm",
        "logup",
        "pcs_rows",
        "pcs_ntt",
        "pcs_merkle",
        "auth_masks",
        "mailbox",
    )
    return (
        _x4c_has(row, integer_keys + ("operations",))
        and all(_x4c_nonnegative_int(row[key]) for key in integer_keys)
        and isinstance(row["operations"], list)
        and len(row["operations"]) == len(expected_operations)
        and tuple(item[0] for item in row["operations"]) == expected_operations
        and all(
            isinstance(item, list)
            and len(item) == 2
            and _x4c_nonnegative_int(item[1])
            for item in row["operations"]
        )
        and row["timing_event_api_calls"] == 0
        and row["outstanding_timing_records"] == 0
    )


def _x4c_gpt2_io_snapshot_valid(row: Any, *, response: bool) -> bool:
    integer_keys = (
        "rchar",
        "wchar",
        "syscr",
        "syscw",
        "read_bytes",
        "write_bytes",
        "cancelled_write_bytes",
        "observer_rchar_bytes",
        "unexpected_rchar_bytes",
        "unexpected_wchar_bytes",
        "unexpected_read_bytes",
        "unexpected_write_bytes",
    )
    if not (
        _x4c_has(row, integer_keys + ("response_window_exact",))
        and all(_x4c_nonnegative_int(row[key]) for key in integer_keys)
        and isinstance(row["response_window_exact"], bool)
    ):
        return False
    if not response:
        return True
    return (
        row["unexpected_rchar_bytes"]
        == row["unexpected_wchar_bytes"]
        == row["unexpected_read_bytes"]
        == row["unexpected_write_bytes"]
        == row["cancelled_write_bytes"]
        == 0
        and row["response_window_exact"] is True
    )


def _x4c_gpt2_onboarding_pass_valid(
    row: Any, *, role: str, measured: bool, retained: bool
) -> bool:
    return (
        _x4c_has(
            row,
            (
                "role",
                "measured",
                "wall_s",
                "io",
                "backend",
                "roots",
                "coefficient_bytes",
                "oracle_bytes",
                "root_bytes",
                "retained_durable",
                "cleanup_complete",
                "accepted",
            ),
        )
        and row["role"] == role
        and row["measured"] is measured
        and isinstance(row["wall_s"], (int, float))
        and not isinstance(row["wall_s"], bool)
        and row["wall_s"] > 0
        and _x4c_gpt2_io_snapshot_valid(row["io"], response=False)
        and _x4c_gpt2_backend_valid(row["backend"])
        and isinstance(row["roots"], list)
        and len(row["roots"]) == 5
        and all(_x4c_hex(root, 64) for root in row["roots"])
        and row["coefficient_bytes"] == X4C_DURABLE_COEFFICIENT_BYTES
        and row["oracle_bytes"] == X4C_INITIAL_ORACLE_BYTES
        and row["root_bytes"] == X4C_DURABLE_ROOT_BYTES
        and row["retained_durable"] is retained
        and row["cleanup_complete"] is True
        and row["accepted"] is True
    )


def _x4c_gpt2_onboarding_valid(row: Any, *, schema: int = 2) -> bool:
    schema3_required = (
        "producer_source_sha256",
        "crypto_build_id_scheme",
        "crypto_build_id",
        "crypto_build_manifest_blake3",
        "crypto_build_file_count",
        "crypto_build_source_bytes",
        "campaign_target_s",
        "campaign_started_unix_s",
        "campaign_finished_unix_s",
        "campaign_elapsed_s",
        "campaign_target_met",
    )
    required = (
        "schema",
        "milestone",
        "git_sha",
        "git_dirty",
        "profile",
        "protocol",
        "design_sha256",
        *X4C_GPT2_INPUT_SHA256.keys(),
        "model_config_digest",
        "weights_digest",
        "parent_domains",
        "descriptor_digests",
        "mask_seed_commitment_blake3",
        "warmup",
        "measured",
        "selected_upper_median_wall_s",
        "warmup_root_set",
        "measured_root_sets",
        "durable",
        "durable_census",
        "durable_bytes",
        "durable_tier_exact",
        "roots_identical",
        "golden_match",
        "overall_pass",
        *(schema3_required if schema == 3 else ()),
    )
    if not (
        _x4c_has(row, required)
        and row["schema"] == schema
        and row["milestone"]
        == (
            X4C_GPT2_V3_ONBOARDING_MILESTONE
            if schema == 3
            else X4C_GPT2_ONBOARDING_MILESTONE
        )
        and _x4c_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and (
            (
                _x4c_hex(row["producer_source_sha256"], 64)
                and row["crypto_build_id_scheme"]
                == X4C_CRYPTO_BUILD_ID_SCHEME
                and _x4c_hex(row["crypto_build_id"], 64)
                and _x4c_hex(row["crypto_build_manifest_blake3"], 64)
                and _x4c_positive_int(row["crypto_build_file_count"])
                and _x4c_positive_int(row["crypto_build_source_bytes"])
                and row["campaign_target_s"] == X4C_CAMPAIGN_TARGET_S
                and _x4c_positive_int(row["campaign_started_unix_s"])
                and row["campaign_finished_unix_s"]
                >= row["campaign_started_unix_s"]
                and row["campaign_elapsed_s"]
                == row["campaign_finished_unix_s"]
                - row["campaign_started_unix_s"]
                and row["campaign_target_met"]
                is (
                    row["campaign_elapsed_s"]
                    <= X4C_CAMPAIGN_TARGET_S
                )
            )
            if schema == 3
            else True
        )
        and row["profile"] == X4C_POD_PROFILE
        and row["protocol"] == X4C_GPT2_PROTOCOL
        and row["design_sha256"] == X4C_V1_DESIGN_SHA256
        and all(row[key] == digest for key, digest in X4C_GPT2_INPUT_SHA256.items())
        and row["model_config_digest"] == X4C_GPT2_INPUT_SHA256["input_json_sha256"]
        and row["weights_digest"] == X4C_GPT2_INPUT_SHA256["input_bin_sha256"]
        and isinstance(row["parent_domains"], list)
        and len(row["parent_domains"]) == 51
        and all(
            isinstance(pair, list)
            and len(pair) == 2
            and all(_x4c_nonnegative_int(value) for value in pair)
            for pair in row["parent_domains"]
        )
        and isinstance(row["descriptor_digests"], list)
        and len(row["descriptor_digests"]) == 51
        and len(set(row["descriptor_digests"])) == 51
        and all(_x4c_hex(digest, 64) for digest in row["descriptor_digests"])
        and _x4c_hex(row["mask_seed_commitment_blake3"], 64)
        and _x4c_gpt2_onboarding_pass_valid(
            row["warmup"], role="warmup", measured=False, retained=False
        )
        and isinstance(row["measured"], list)
        and len(row["measured"]) == 3
        and all(
            _x4c_gpt2_onboarding_pass_valid(
                candidate,
                role=f"measured-{ordinal}",
                measured=True,
                retained=ordinal == 3,
            )
            for ordinal, candidate in enumerate(row["measured"], 1)
        )
        and _x4c_durable_census_valid(row["durable_census"])
        and row["durable_bytes"] == X4C_DURABLE_BYTES
        and row["durable_tier_exact"] is True
        and row["roots_identical"] is True
        and row["golden_match"] is True
        and row["overall_pass"] is True
    ):
        return False
    roots = row["warmup"]["roots"]
    if (
        row["warmup_root_set"] != roots
        or row["measured_root_sets"] != [candidate["roots"] for candidate in row["measured"]]
        or any(candidate["roots"] != roots for candidate in row["measured"])
        or row["selected_upper_median_wall_s"]
        != sorted(candidate["wall_s"] for candidate in row["measured"])[1]
        or not isinstance(row["durable"], list)
        or len(row["durable"]) != 5
    ):
        return False
    for durable, expected, root in zip(row["durable"], X4C_COHORTS, roots, strict=True):
        cohort_id, coefficient_bytes, _ = expected
        if not (
            _x4c_has(
                durable,
                (
                    "cohort_id",
                    "coefficient_bytes",
                    "coefficient_sha256",
                    "root_bytes",
                    "root_hex",
                    "root_sha256",
                ),
            )
            and durable["cohort_id"] == cohort_id
            and durable["coefficient_bytes"] == coefficient_bytes
            and _x4c_hex(durable["coefficient_sha256"], 64)
            and durable["root_bytes"] == 32
            and durable["root_hex"] == root
            and _x4c_hex(durable["root_sha256"], 64)
        ):
            return False
    return True


def validate_x4c_gpt2_onboarding_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4c_gpt2_onboarding_valid(json.loads(path.read_bytes()))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def validate_x4c_gpt2_v3_onboarding_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4c_gpt2_onboarding_valid(
            json.loads(path.read_bytes()), schema=3
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


_X4C_GPT2_ARENA_INT_KEYS = (
    "capacity_bytes",
    "committed_bytes",
    "peak_bytes",
    "logical_allocations",
    "response_round_allocations",
    "reallocations",
    "logical_deallocations",
    "reset_count",
    "zeroed_bytes",
    "outstanding_allocations",
    "outstanding_bytes",
    "cached_reusable_bytes",
    "baseline_active_device_allocations",
    "baseline_active_pinned_allocations",
    "baseline_active_pinned_bytes",
    "active_device_allocations",
    "active_pinned_allocations",
    "active_pinned_bytes",
    "outstanding_cuda_operations",
    "pinned_pool_allocations",
    "pinned_pool_requested_bytes",
    "native_live_device_bytes",
    "native_peak_device_bytes",
    "native_resident_alloc_requests",
    "native_resident_reuse_hits",
    "native_resident_free_requests",
    "native_arena_reset_calls",
    "native_arena_reset_bytes",
    "native_device_zeroed_bytes",
)


def _x4c_gpt2_arena_valid(
    row: Any,
    *,
    proof_ready: bool,
    native_resident_cache: bool = False,
) -> bool:
    if not (
        _x4c_has(
            row,
            _X4C_GPT2_ARENA_INT_KEYS
            + ("accelerator_available", "stream_synchronized"),
        )
        and all(_x4c_nonnegative_int(row[key]) for key in _X4C_GPT2_ARENA_INT_KEYS)
        and row["accelerator_available"] is True
        and row["stream_synchronized"] is True
        and row["capacity_bytes"] == row["committed_bytes"] == X4C_ARENA_BYTES
        and row["peak_bytes"] == row["native_peak_device_bytes"]
        and row["peak_bytes"] >= X4C_ARENA_BYTES
        and row["logical_allocations"] == row["native_resident_alloc_requests"] == 1
        and row["response_round_allocations"] == 0
        and row["reallocations"] == 0
        and row["logical_deallocations"] == row["native_resident_free_requests"]
        and row["reset_count"] == row["native_arena_reset_calls"]
        and row["zeroed_bytes"] == row["native_device_zeroed_bytes"]
        and row["outstanding_cuda_operations"] == 0
        and row["pinned_pool_allocations"] == 4
        and row["pinned_pool_requested_bytes"] == 1_090_741_982
        and row["active_pinned_allocations"]
        == row["baseline_active_pinned_allocations"] + 4
        and row["active_pinned_bytes"]
        >= row["baseline_active_pinned_bytes"] + row["pinned_pool_requested_bytes"]
    ):
        return False
    if proof_ready:
        return (
            row["logical_deallocations"] == row["reset_count"] == row["zeroed_bytes"] == 0
            and row["native_arena_reset_bytes"] == 0
            and row["outstanding_allocations"] == 1
            and row["outstanding_bytes"] == X4C_ARENA_BYTES
            and row["cached_reusable_bytes"] == 0
            and (
                row["native_live_device_bytes"] >= X4C_ARENA_BYTES
                if native_resident_cache
                else row["native_live_device_bytes"] == X4C_ARENA_BYTES
            )
            and row["active_device_allocations"]
            == row["baseline_active_device_allocations"] + 1
        )
    return (
        row["logical_deallocations"] == row["reset_count"] == 1
        and row["zeroed_bytes"] == X4C_ARENA_BYTES
        and row["native_arena_reset_bytes"] == X4C_ARENA_BYTES
        and row["outstanding_allocations"] == row["outstanding_bytes"] == 0
        and row["cached_reusable_bytes"] == X4C_ARENA_BYTES
        and (
            row["native_live_device_bytes"] >= X4C_ARENA_BYTES
            if native_resident_cache
            else row["native_live_device_bytes"] == 0
        )
        and row["active_device_allocations"] == row["baseline_active_device_allocations"]
    )


def _x4c_gpt2_candidate_valid(
    row: Any,
    *,
    role: str,
    ordinal: int,
    measured: bool,
    epoch_base: int,
    model_sub_correlations: int,
    model_full_correlations: int,
    accelerated: bool = False,
) -> bool:
    required = (
        "role",
        "ordinal",
        "measured",
        "epoch",
        "challenge_seed_digest",
        "response_nonce_digest",
        "freshness_binding_digest",
        "freshness_record_digest",
        "authorization_record_digest",
        "freshness_markers_persisted",
        "model_root",
        "model_prove_s",
        "model_verify_s",
        "model_transcript_prover_bytes",
        "model_transcript_replay_bytes",
        "model_transcript_replay_labels",
        "model_transcript_accounting_exact",
        "pcs_total_s",
        "seal_wall_s",
        "open_wall_s",
        "verify_wall_s",
        "proof_ready_wall_s",
        "session_reusable_wall_s",
        "complete_e2e_wall_s",
        "complete_pcs_bytes",
        "response_bytes",
        "sub_correlations",
        "full_correlations",
        "expected_sub_correlations",
        "expected_full_correlations",
        "correlation_allocation_digest",
        "prover_verifier_correlation_digest_equal",
        "transcript_bytes_equal",
        "transcript_ledger_equal",
        "process_io",
        "response_window_io_exact",
        "backend",
        "metrics",
        "expected_h2d_bytes",
        "expected_d2h_bytes",
        *(
            (
                "expected_explicit_d2d_copy_bytes",
                "expected_device_generated_bytes",
            )
            if accelerated
            else ()
        ),
        "traffic_exact",
        "zero_response_staging",
        "verifier_accepted",
        "connection_audit",
        "accepted",
    )
    timing_keys = (
        "model_prove_s",
        "model_verify_s",
        "pcs_total_s",
        "seal_wall_s",
        "open_wall_s",
        "verify_wall_s",
        "proof_ready_wall_s",
        "session_reusable_wall_s",
        "complete_e2e_wall_s",
    )
    expected_full = model_full_correlations + 2_314 + 2
    if not (
        _x4c_has(row, required)
        and row["role"] == role
        and row["ordinal"] == ordinal
        and row["measured"] is measured
        and row["epoch"] == epoch_base + ordinal
        and all(_x4c_hex(row[key], 64) for key in (
            "challenge_seed_digest",
            "response_nonce_digest",
            "freshness_binding_digest",
            "freshness_record_digest",
            "authorization_record_digest",
            "model_root",
            "correlation_allocation_digest",
        ))
        and row["freshness_markers_persisted"] is True
        and all(
            isinstance(row[key], (int, float))
            and not isinstance(row[key], bool)
            and row[key] > 0
            for key in timing_keys
        )
        and row["session_reusable_wall_s"] >= row["proof_ready_wall_s"]
        and row["model_transcript_prover_bytes"]
        == X4C_GPT2_MODEL_TRANSCRIPT_PROVER_BYTES
        and row["model_transcript_replay_bytes"]
        == X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_BYTES
        and row["model_transcript_replay_labels"]
        == X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_LABELS
        and row["model_transcript_accounting_exact"] is True
        and row["complete_pcs_bytes"] == X4_V4_PCS_BYTES
        and row["response_bytes"] == X4_V4_RESPONSE_BYTES
        and row["sub_correlations"]
        == row["expected_sub_correlations"]
        == model_sub_correlations
        and row["full_correlations"]
        == row["expected_full_correlations"]
        == expected_full
        and row["prover_verifier_correlation_digest_equal"] is True
        and row["transcript_bytes_equal"] is True
        and row["transcript_ledger_equal"] is True
        and _x4c_gpt2_io_snapshot_valid(row["process_io"], response=True)
        and row["response_window_io_exact"] is True
        and _x4c_gpt2_backend_valid(row["backend"])
        and row["traffic_exact"] is True
        and row["zero_response_staging"] is True
        and row["verifier_accepted"] is True
        and row["accepted"] is True
    ):
        return False
    metrics = row["metrics"]
    if not _x4c_has(
        metrics,
        (
            "response_io",
            "execution",
            "proof_ready_arena",
            "session_reusable_arena",
            "proof_ready_wall_ns",
            "session_reusable_wall_ns",
            "source_coefficients_read",
            "initial_encoded_symbols_read",
            "combined_codeword_symbols",
            "serialized_fold_bytes",
            "serialized_packed_opening_bytes",
            "sampling_soundness_credit_bits",
        ),
    ):
        return False
    response_io = metrics["response_io"]
    execution = metrics["execution"]
    backend = row["backend"]
    proof_ready_arena = metrics["proof_ready_arena"]
    session_reusable_arena = metrics["session_reusable_arena"]
    expected_execution = {
        "direct_fold_calls": 27,
        "diagnostic_comparisons": 1_592,
        "diagnostic_mismatches": 0,
        "diagnostic_gather_calls": 53,
        "diagnostic_index_h2d_bytes": 37_184,
        "diagnostic_value_d2h_bytes": 74_368,
        "n4_tree_calls": 27,
        "query_gather_calls": 1,
        "query_gather_operation_count": 53_898,
        "query_gather_operation_h2d_bytes": 4_743_024,
        "canonical_template_h2d_bytes": X4C_PACKED_OPENING_BYTES,
        "query_draw_count": 111,
        "canonical_opening_d2h_bytes": X4C_PACKED_OPENING_BYTES,
        "noncanonical_opening_d2h_bytes": 0,
        "cpu_fold_tree_clone_bytes": 0,
    }
    if accelerated:
        expected_device_generated_bytes = (
            X4C_PRODUCTION_FRESH_DEVICE_GENERATED_BYTES
            if ordinal == 0
            else X4C_PRODUCTION_REUSED_DEVICE_GENERATED_BYTES
        )
        expected_execution.update(
            {
                "expected_explicit_d2d_copy_bytes":
                    X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES,
                "expected_device_generated_bytes":
                    expected_device_generated_bytes,
            }
        )
    audit = row["connection_audit"]
    expected_h2d = (
        metrics["combined_codeword_symbols"] * 16
        + execution["diagnostic_index_h2d_bytes"]
        + execution["query_gather_operation_h2d_bytes"]
        + execution["canonical_template_h2d_bytes"]
    )
    expected_d2h = (
        27 * 32
        + execution["diagnostic_value_d2h_bytes"]
        + execution["canonical_opening_d2h_bytes"]
    )
    return (
        isinstance(response_io, dict)
        and len(response_io) == 14
        and all(_x4c_nonnegative_int(value) and value == 0 for value in response_io.values())
        and isinstance(execution, dict)
        and all(execution.get(key) == value for key, value in expected_execution.items())
        and _x4c_gpt2_arena_valid(
            proof_ready_arena,
            proof_ready=True,
            native_resident_cache=accelerated,
        )
        and _x4c_gpt2_arena_valid(
            session_reusable_arena,
            proof_ready=False,
            native_resident_cache=accelerated,
        )
        and (
            proof_ready_arena["native_live_device_bytes"]
            == session_reusable_arena["native_live_device_bytes"]
            == backend["live_device_bytes"]
            and proof_ready_arena["native_peak_device_bytes"]
            == session_reusable_arena["native_peak_device_bytes"]
            == backend["peak_device_bytes"]
            if accelerated
            else True
        )
        and metrics["proof_ready_wall_ns"] > 0
        and metrics["session_reusable_wall_ns"] >= metrics["proof_ready_wall_ns"]
        and metrics["source_coefficients_read"] == 601_161_728
        and metrics["initial_encoded_symbols_read"] == 4_809_293_824
        and metrics["combined_codeword_symbols"] == 1_159_200_768
        and metrics["serialized_fold_bytes"] == 2_446
        and metrics["serialized_packed_opening_bytes"] == X4C_PACKED_OPENING_BYTES
        and metrics["sampling_soundness_credit_bits"] == 0
        and row["expected_h2d_bytes"] == backend["h2d_bytes"] == expected_h2d
        and row["expected_d2h_bytes"] == backend["d2h_bytes"] == expected_d2h
        and (
            (
                row["expected_explicit_d2d_copy_bytes"]
                == execution["expected_explicit_d2d_copy_bytes"]
                == backend["explicit_d2d_copy_bytes"]
                == X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES
                and row["expected_device_generated_bytes"]
                == execution["expected_device_generated_bytes"]
                == backend["device_generated_bytes"]
                == expected_device_generated_bytes
            )
            if accelerated
            else (
                backend["explicit_d2d_copy_bytes"] == 0
                and backend["device_generated_bytes"] == 0
            )
        )
        and backend["resident_alloc_requests"] == backend["resident_free_requests"] == 1
        and backend["x4c_arena_reset_calls"] == 1
        and backend["x4c_arena_reset_bytes"]
        == backend["device_zeroed_bytes"]
        == X4C_ARENA_BYTES
        and all(
            backend[key] == 0
            for key in (
                "pinned_allocation_calls",
                "pinned_alloc_requests",
                "pinned_reuse_hits",
                "pinned_free_requests",
                "pinned_physical_free_calls",
            )
        )
        and _x4c_has(
            audit,
            (
                "response_nonce_digest",
                "allocation_digest",
                "channel_ledger_digest",
                "correlations_consumed",
                "channel_frames",
            ),
        )
        and audit["response_nonce_digest"] == row["response_nonce_digest"]
        and _x4c_hex(audit["allocation_digest"], 64)
        and _x4c_hex(audit["channel_ledger_digest"], 64)
        and audit["correlations_consumed"]
        == model_sub_correlations + 2 * expected_full
        and _x4c_nonnegative_int(audit["channel_frames"])
    )


_X4C_GPT2_CANDIDATE_GATE_KEYS = (
    "verifier_accepted",
    "freshness_markers_persisted",
    "model_transcript_accounting_exact",
    "transcript_bytes_equal",
    "transcript_ledger_equal",
    "correlation_counters_equal",
    "sub_correlations_exact",
    "full_correlations_exact",
    "correlation_allocation_digest_equal",
    "pcs_bytes_exact",
    "query_gather_exact",
    "direct_fold_comparisons_exact",
    "direct_fold_mismatches_zero",
    "zero_soundness_credit",
    "zero_response_staging",
    "traffic_exact",
)


def _x4c_gpt2_candidate_gate_audit_valid(row: Any) -> bool:
    return (
        _x4c_has(row, _X4C_GPT2_CANDIDATE_GATE_KEYS + ("failed", "all_pass"))
        and all(row[key] is True for key in _X4C_GPT2_CANDIDATE_GATE_KEYS)
        and row["failed"] == []
        and row["all_pass"] is True
    )


def _x4c_gpt2_rebuild_valid(row: Any, onboarding: dict[str, Any]) -> bool:
    if not (
        _x4c_has(
            row,
            (
                "wall_s",
                "io",
                "parallel_task_count",
                "rayon_workers",
                "cohorts",
                "coefficient_bytes_read",
                "evaluation_table_bytes",
                "host_oracle_bytes",
                "host_outer_cache_bytes",
                "roots_equal_onboarding",
                "durable_census_before",
                "durable_census_after",
                "durable_census_stable",
                "accepted",
            ),
        )
        and isinstance(row["wall_s"], (int, float))
        and not isinstance(row["wall_s"], bool)
        and row["wall_s"] > 0
        and _x4c_gpt2_io_snapshot_valid(row["io"], response=False)
        and row["parallel_task_count"] == 5
        and _x4c_positive_int(row["rayon_workers"])
        and row["coefficient_bytes_read"] == X4C_DURABLE_COEFFICIENT_BYTES
        and row["evaluation_table_bytes"] == X4C_DURABLE_COEFFICIENT_BYTES
        and row["host_oracle_bytes"] == X4C_INITIAL_ORACLE_BYTES
        and row["host_outer_cache_bytes"] == X4C_INITIAL_OUTER_CACHE_BYTES
        and _x4c_durable_census_valid(row["durable_census_before"])
        and row["durable_census_before"] == onboarding["durable_census"]
        and row["durable_census_after"] == row["durable_census_before"]
        and row["durable_census_stable"] is True
        and row["roots_equal_onboarding"] is True
        and row["accepted"] is True
        and isinstance(row["cohorts"], list)
        and len(row["cohorts"]) == 5
        and "accelerated" not in row
    ):
        return False
    for cohort, durable, expected in zip(
        row["cohorts"], onboarding["durable"], X4C_COHORTS, strict=True
    ):
        cohort_id, coefficient_bytes, cache_bytes = expected
        if not (
            _x4c_has(
                cohort,
                (
                    "cohort_id",
                    "coefficient_bytes_read",
                    "host_oracle_bytes",
                    "host_outer_cache_bytes",
                    "root",
                    "expected_root",
                    "root_equal",
                    "accepted",
                ),
            )
            and cohort["cohort_id"] == cohort_id == durable["cohort_id"]
            and cohort["coefficient_bytes_read"] == coefficient_bytes
            and cohort["host_oracle_bytes"] == coefficient_bytes * 8
            and cohort["host_outer_cache_bytes"] == cache_bytes
            and cohort["root"]
            == cohort["expected_root"]
            == durable["root_hex"]
            and cohort["root_equal"] is True
            and cohort["accepted"] is True
        ):
            return False
    return True


def _x4c_gpt2_rebuild_control_valid(row: Any) -> bool:
    integer_keys = (
        "outstanding_cuda_operations",
        "pending_timing_records",
        "active_device_allocations",
        "cached_device_allocations",
        "workspace_device_bytes",
        "active_device_bytes",
        "cached_device_bytes",
        "active_pinned_allocations",
        "cached_pinned_allocations",
        "in_flight_pinned_allocations",
        "active_pinned_bytes",
        "cached_pinned_bytes",
    )
    boolean_keys = (
        "measurement_active",
        "coarse_timing_active",
        "timing_record_active",
        "measurement_poisoned",
    )
    return (
        _x4c_has(row, ("stream_state", *integer_keys, *boolean_keys))
        and row["stream_state"] == "idle"
        and all(_x4c_nonnegative_int(row[key]) for key in integer_keys)
        and all(row[key] is False for key in boolean_keys)
        and row["outstanding_cuda_operations"] == 0
        and row["pending_timing_records"] == 0
        and row["in_flight_pinned_allocations"] == 0
    )


def _x4c_gpt2_rebuild_memory_valid(row: Any) -> bool:
    return _x4c_has(
        row, ("workspace_bytes", "resident_bytes", "cached_resident_bytes")
    ) and all(
        _x4c_nonnegative_int(row[key])
        for key in ("workspace_bytes", "resident_bytes", "cached_resident_bytes")
    )


def _x4c_gpt2_process_memory_valid(row: Any) -> bool:
    return (
        _x4c_has(row, ("rss_bytes", "peak_rss_bytes"))
        and _x4c_positive_int(row["rss_bytes"])
        and _x4c_positive_int(row["peak_rss_bytes"])
        and row["peak_rss_bytes"] >= row["rss_bytes"]
    )


def _x4c_gpt2_accelerated_cohort_valid(
    row: Any, expected: tuple[int, int, int]
) -> bool:
    required = (
        "cohort_id",
        "strategy",
        "wall_s",
        "phases",
        "process_memory_before",
        "process_memory_after",
        "backend",
        "device_memory_before",
        "device_memory_after",
        "control_before",
        "control_after",
        "structural_slots",
        "present_slots",
        "coefficient_bytes",
        "host_oracle_bytes",
        "host_outer_cache_bytes",
        "ntt_calls",
        "n4_inner_calls",
        "n4_outer_calls",
        "expected_h2d_bytes",
        "expected_d2h_bytes",
        "scratch_files_created",
        "scratch_bytes_read",
        "scratch_bytes_written",
        "file_backed_bytes",
        "owned_file_count",
        "owned_mapping_count",
        "root_equal",
        "traffic_exact",
        "cleanup_complete",
        "accepted",
    )
    phase_keys = (
        "e_ntt_ns",
        "n4_inner_ns",
        "n4_outer_ns",
        "assemble_and_root_check_ns",
        "cleanup_ns",
        "total_ns",
    )
    cohort_id, coefficient_bytes, cache_bytes = expected
    structural_and_present = {
        0xA5000001: (2, 2),
        0xA5000002: (64, 36),
        0xA5000003: (16, 13),
        0xA5000100: (2, 2),
        0xA5000101: (64, 49),
        0xA5FF0001: (4, 3),
    }
    if not (
        _x4c_has(row, required)
        and row["cohort_id"] == cohort_id
        and row["strategy"] == "cuda-ram-v1"
        and isinstance(row["wall_s"], (int, float))
        and not isinstance(row["wall_s"], bool)
        and row["wall_s"] > 0
        and isinstance(row["phases"], dict)
        and _x4c_has(row["phases"], phase_keys)
        and all(_x4c_positive_int(row["phases"][key]) for key in phase_keys)
        and row["phases"]["total_ns"]
        >= sum(row["phases"][key] for key in phase_keys[:-1])
        and abs(row["wall_s"] - row["phases"]["total_ns"] / 1e9) <= 1e-12
        and _x4c_gpt2_process_memory_valid(row["process_memory_before"])
        and _x4c_gpt2_process_memory_valid(row["process_memory_after"])
        and _x4c_gpt2_backend_valid(row["backend"])
        and _x4c_gpt2_rebuild_memory_valid(row["device_memory_before"])
        and _x4c_gpt2_rebuild_memory_valid(row["device_memory_after"])
        and _x4c_gpt2_rebuild_control_valid(row["control_before"])
        and _x4c_gpt2_rebuild_control_valid(row["control_after"])
        and (row["structural_slots"], row["present_slots"])
        == structural_and_present[cohort_id]
        and row["coefficient_bytes"] == coefficient_bytes
        and row["host_oracle_bytes"] == coefficient_bytes * 8
        and row["host_outer_cache_bytes"] == cache_bytes
        and row["ntt_calls"] == row["present_slots"]
        and _x4c_positive_int(row["n4_inner_calls"])
        and _x4c_positive_int(row["n4_outer_calls"])
        and _x4c_positive_int(row["expected_h2d_bytes"])
        and _x4c_positive_int(row["expected_d2h_bytes"])
        and row["backend"]["h2d_bytes"] == row["expected_h2d_bytes"]
        and row["backend"]["d2h_bytes"] == row["expected_d2h_bytes"]
        and row["backend"]["timing_event_api_calls"] == 0
        and row["backend"]["outstanding_timing_records"] == 0
        and row["scratch_files_created"] == 0
        and row["scratch_bytes_read"] == 0
        and row["scratch_bytes_written"] == 0
        and row["file_backed_bytes"] == 0
        and row["owned_file_count"] == 0
        and row["owned_mapping_count"] == 0
        and row["root_equal"] is True
        and row["traffic_exact"] is True
        and row["cleanup_complete"] is True
        and row["accepted"] is True
    ):
        return False
    before = row["control_before"]
    after = row["control_after"]
    memory_before = row["device_memory_before"]
    memory_after = row["device_memory_after"]
    return (
        all(
            before[key] == after[key]
            for key in (
                "active_device_allocations",
                "active_device_bytes",
                "active_pinned_allocations",
                "active_pinned_bytes",
            )
        )
        and before["workspace_device_bytes"]
        == memory_before["workspace_bytes"]
        and before["active_device_bytes"] == memory_before["resident_bytes"]
        and before["cached_device_bytes"]
        == memory_before["cached_resident_bytes"]
        and after["workspace_device_bytes"] == memory_after["workspace_bytes"]
        and after["active_device_bytes"] == memory_after["resident_bytes"]
        and after["cached_device_bytes"]
        == memory_after["cached_resident_bytes"]
        and row["backend"]["live_device_bytes"]
        == memory_after["workspace_bytes"]
        + memory_after["resident_bytes"]
        + memory_after["cached_resident_bytes"]
        and row["backend"]["peak_device_bytes"]
        >= row["backend"]["live_device_bytes"]
        and row["backend"]["live_pinned_bytes"]
        == after["active_pinned_bytes"] + after["cached_pinned_bytes"]
        and row["backend"]["peak_pinned_bytes"]
        >= row["backend"]["live_pinned_bytes"]
    )


def _x4c_gpt2_accelerated_rebuild_valid(
    row: Any, onboarding: dict[str, Any]
) -> bool:
    required = (
        "contract",
        "strategy",
        "deterministic_schedule",
        "cuda_cohort_concurrency",
        "mu26_mu22_overlap",
        "automatic_cpu_fallback",
        "cpu_fallback_opt_in_only",
        "evaluation_table_wall_s",
        "cohorts",
        "expected_h2d_bytes",
        "expected_d2h_bytes",
        "peak_host_rss_bytes",
        "peak_device_bytes",
        "scratch_files_created",
        "scratch_bytes_read",
        "scratch_bytes_written",
        "outstanding_cuda_operations",
        "rebuild_workspace_bytes_before_context_drop",
        "rebuild_live_device_bytes_before_context_drop",
        "backend_context_cleanup_wall_s",
        "backend_context_dropped_before_response",
        "online_backend_fresh_context",
        "fresh_online_backend_device_bytes",
        "fresh_online_backend_outstanding_cuda_operations",
        "cleanup_complete",
        "traffic_exact",
        "accepted",
    )
    if not (
        isinstance(row, dict)
        and row.get("parallel_task_count") == 1
        and isinstance(row.get("accelerated"), dict)
    ):
        return False
    historical_shape = dict(row)
    accelerated = historical_shape.pop("accelerated")
    historical_shape["parallel_task_count"] = 5
    if not _x4c_gpt2_rebuild_valid(historical_shape, onboarding):
        return False
    expected_by_id = {cohort[0]: cohort for cohort in X4C_COHORTS}
    schedule = [0xA5000001, 0xA5000002, 0xA5000003, 0xA5000101, 0xA5000100]
    if not (
        _x4c_has(accelerated, required)
        and accelerated["contract"] == "x4c-gpt2-accelerated-rebuild-schema-1"
        and accelerated["strategy"] == "cuda-ram-v1"
        and accelerated["deterministic_schedule"] == schedule
        and accelerated["cuda_cohort_concurrency"] == 1
        and accelerated["mu26_mu22_overlap"] is False
        and accelerated["automatic_cpu_fallback"] is False
        and accelerated["cpu_fallback_opt_in_only"] is True
        and isinstance(accelerated["evaluation_table_wall_s"], (int, float))
        and not isinstance(accelerated["evaluation_table_wall_s"], bool)
        and accelerated["evaluation_table_wall_s"] > 0
        and isinstance(accelerated["cohorts"], list)
        and len(accelerated["cohorts"]) == 5
        and all(
            _x4c_gpt2_accelerated_cohort_valid(
                cohort, expected_by_id[cohort_id]
            )
            for cohort, cohort_id in zip(
                accelerated["cohorts"], schedule, strict=True
            )
        )
        and accelerated["expected_h2d_bytes"]
        == sum(cohort["expected_h2d_bytes"] for cohort in accelerated["cohorts"])
        and accelerated["expected_d2h_bytes"]
        == sum(cohort["expected_d2h_bytes"] for cohort in accelerated["cohorts"])
        and accelerated["peak_host_rss_bytes"]
        == max(
            max(
                cohort["process_memory_before"]["peak_rss_bytes"],
                cohort["process_memory_after"]["peak_rss_bytes"],
            )
            for cohort in accelerated["cohorts"]
        )
        and accelerated["peak_device_bytes"]
        == max(cohort["backend"]["peak_device_bytes"] for cohort in accelerated["cohorts"])
        and accelerated["scratch_files_created"] == 0
        and accelerated["scratch_bytes_read"] == 0
        and accelerated["scratch_bytes_written"] == 0
        and accelerated["outstanding_cuda_operations"] == 0
        and accelerated["rebuild_workspace_bytes_before_context_drop"]
        == accelerated["cohorts"][-1]["device_memory_after"]["workspace_bytes"]
        and accelerated["rebuild_live_device_bytes_before_context_drop"]
        == accelerated["cohorts"][-1]["backend"]["live_device_bytes"]
        and isinstance(
            accelerated["backend_context_cleanup_wall_s"], (int, float)
        )
        and not isinstance(accelerated["backend_context_cleanup_wall_s"], bool)
        and accelerated["backend_context_cleanup_wall_s"] >= 0
        and accelerated["backend_context_dropped_before_response"] is True
        and accelerated["online_backend_fresh_context"] is True
        and accelerated["fresh_online_backend_device_bytes"] == 0
        and accelerated[
            "fresh_online_backend_outstanding_cuda_operations"
        ]
        == 0
        and accelerated["cleanup_complete"] is True
        and accelerated["traffic_exact"] is True
        and accelerated["accepted"] is True
    ):
        return False
    return True


def _x4c_gpt2_online_valid(
    row: Any,
    onboarding: dict[str, Any],
    onboarding_sha256: str,
    *,
    accelerated: bool = False,
    schema: int = 2,
    rebuild_admission: dict[str, Any] | None = None,
    rebuild_admission_sha256: str | None = None,
) -> bool:
    schema3_required = (
        "producer_source_sha256",
        "crypto_build_id_scheme",
        "crypto_build_id",
        "crypto_build_manifest_blake3",
        "crypto_build_file_count",
        "crypto_build_source_bytes",
        "campaign_target_s",
        "campaign_started_unix_s",
        "campaign_rebuild_finished_unix_s",
        "campaign_elapsed_through_rebuild_s",
        "rebuild_campaign_target_met",
        "rebuild_admission_marker_path",
        "rebuild_admission_marker_sha256",
    )
    required = (
        "schema",
        "milestone",
        "git_sha",
        "git_dirty",
        "profile",
        "protocol",
        "design_sha256",
        "onboarding_path",
        "onboarding_sha256",
        "onboarding_sha256_exact",
        "onboarding_git_sha",
        "clean_source_sha256",
        "selected_query_tape_blake3",
        *X4C_GPT2_INPUT_SHA256.keys(),
        "prefill_tokens",
        "decode_tokens",
        "pcg_prg",
        "pcg_stage_plan",
        "model_sub_correlations",
        "model_full_correlations",
        "x4c_full_correlations",
        "closure_full_correlations",
        "golden_match",
        "cpu_cuda_prefill_logits_equal",
        "cpu_cuda_band_logits_equal",
        "rebuild",
        "rebuild_roots",
        "rebuild_roots_equal_onboarding",
        "rebuild_parallel_tasks",
        "warmup_count",
        "measured_count",
        "candidates",
        "selected_upper_median_open_wall_s",
        "selected_upper_median_verify_wall_s",
        "selected_upper_median_proof_ready_wall_s",
        "selected_upper_median_session_reusable_wall_s",
        "selected_upper_median_complete_e2e_wall_s",
        "open_ceiling_s",
        "verify_ceiling_s",
        "open_pass",
        "verify_pass",
        "pinned_pool_release_wall_s",
        "pinned_pool_release_restored_ownership",
        "pcs_bytes",
        "response_bytes",
        "rate",
        "query_count",
        "all_candidates_accepted",
        "zero_response_staging",
        "exact_communication",
        "diagnostic_comparisons",
        "diagnostic_soundness_credit_bits",
        "protocol_or_parameter_change",
        "root_or_proof_format_change",
        "lean_or_soundness_change",
        "overall_pass",
        *(schema3_required if schema == 3 else ()),
    )
    if not (
        _x4c_gpt2_onboarding_valid(onboarding, schema=schema)
        and _x4c_has(row, required)
        and row["schema"] == schema
        and row["milestone"]
        == (
            (
                X4C_GPT2_V3_ACCELERATED_ONLINE_MILESTONE
                if accelerated
                else X4C_GPT2_V3_ONLINE_MILESTONE
            )
            if schema == 3
            else (
                X4C_GPT2_ACCELERATED_ONLINE_MILESTONE
                if accelerated
                else X4C_GPT2_ONLINE_MILESTONE
            )
        )
        and _x4c_hex(row["git_sha"], 40)
        and row["onboarding_git_sha"] == onboarding["git_sha"]
        and (schema == 3 or row["git_sha"] == onboarding["git_sha"])
        and row["git_dirty"] is False
        and (
            (
                _x4c_hex(row["producer_source_sha256"], 64)
                and row["clean_source_sha256"]
                == row["producer_source_sha256"]
                and row["crypto_build_id_scheme"]
                == onboarding["crypto_build_id_scheme"]
                == X4C_CRYPTO_BUILD_ID_SCHEME
                and row["crypto_build_id"]
                == onboarding["crypto_build_id"]
                and _x4c_hex(row["crypto_build_id"], 64)
                and row["crypto_build_manifest_blake3"]
                == onboarding["crypto_build_manifest_blake3"]
                and _x4c_hex(row["crypto_build_manifest_blake3"], 64)
                and row["crypto_build_file_count"]
                == onboarding["crypto_build_file_count"]
                and _x4c_positive_int(row["crypto_build_file_count"])
                and row["crypto_build_source_bytes"]
                == onboarding["crypto_build_source_bytes"]
                and _x4c_positive_int(row["crypto_build_source_bytes"])
                and row["campaign_target_s"] == X4C_CAMPAIGN_TARGET_S
                and _x4c_positive_int(row["campaign_started_unix_s"])
                and row["campaign_rebuild_finished_unix_s"]
                >= row["campaign_started_unix_s"]
                and row["campaign_elapsed_through_rebuild_s"]
                == row["campaign_rebuild_finished_unix_s"]
                - row["campaign_started_unix_s"]
                and row["rebuild_campaign_target_met"]
                is (
                    row["campaign_elapsed_through_rebuild_s"]
                    <= X4C_CAMPAIGN_TARGET_S
                )
                and isinstance(row["rebuild_admission_marker_path"], str)
                and bool(row["rebuild_admission_marker_path"])
                and row["rebuild_admission_marker_sha256"]
                == rebuild_admission_sha256
                and _x4c_hex(row["rebuild_admission_marker_sha256"], 64)
                and _x4c_has(
                    rebuild_admission,
                    (
                        "schema",
                        "milestone",
                        "producer_git_sha",
                        "producer_source_sha256",
                        "crypto_build_id_scheme",
                        "crypto_build_id",
                        "onboarding_sha256",
                        "campaign_target_s",
                        "campaign_started_unix_s",
                        "campaign_rebuild_finished_unix_s",
                        "campaign_elapsed_through_rebuild_s",
                        "rebuild_campaign_target_met",
                        "rebuild_roots",
                        "rebuild_roots_equal_onboarding",
                        "accepted",
                    ),
                )
                and rebuild_admission["schema"] == 1
                and rebuild_admission["milestone"]
                == X4C_SCHEMA3_REBUILD_ADMISSION_MILESTONE
                and rebuild_admission["producer_git_sha"] == row["git_sha"]
                and rebuild_admission["producer_source_sha256"]
                == row["producer_source_sha256"]
                and rebuild_admission["crypto_build_id_scheme"]
                == row["crypto_build_id_scheme"]
                and rebuild_admission["crypto_build_id"]
                == row["crypto_build_id"]
                and rebuild_admission["onboarding_sha256"]
                == onboarding_sha256
                and rebuild_admission["campaign_target_s"]
                == row["campaign_target_s"]
                and rebuild_admission["campaign_started_unix_s"]
                == row["campaign_started_unix_s"]
                and rebuild_admission["campaign_rebuild_finished_unix_s"]
                == row["campaign_rebuild_finished_unix_s"]
                and rebuild_admission["campaign_elapsed_through_rebuild_s"]
                == row["campaign_elapsed_through_rebuild_s"]
                and rebuild_admission["rebuild_campaign_target_met"]
                is row["rebuild_campaign_target_met"]
                and rebuild_admission["rebuild_roots"]
                == row["rebuild_roots"]
                and rebuild_admission["rebuild_roots_equal_onboarding"] is True
                and rebuild_admission["accepted"] is True
            )
            if schema == 3
            else True
        )
        and row["profile"] == X4C_POD_PROFILE
        and row["protocol"] == X4C_GPT2_PROTOCOL
        and row["design_sha256"]
        == onboarding["design_sha256"]
        == X4C_V1_DESIGN_SHA256
        and row["onboarding_sha256"] == onboarding_sha256
        and row["onboarding_sha256_exact"] is True
        and _x4c_hex(row["clean_source_sha256"], 64)
        and row["selected_query_tape_blake3"] == X4C_GPT2_SELECTED_TAPE
        and all(row[key] == digest for key, digest in X4C_GPT2_INPUT_SHA256.items())
        and row["prefill_tokens"] == 100
        and row["decode_tokens"] == 50
        and row["pcg_prg"] == "aes128-mmo"
        and row["pcg_stage_plan"] == "terminal-one"
        and _x4c_positive_int(row["model_sub_correlations"])
        and _x4c_positive_int(row["model_full_correlations"])
        and row["x4c_full_correlations"] == 2_314
        and row["closure_full_correlations"] == 2
        and row["golden_match"] is True
        and row["cpu_cuda_prefill_logits_equal"] is True
        and row["cpu_cuda_band_logits_equal"] is True
        and (
            _x4c_gpt2_accelerated_rebuild_valid(row["rebuild"], onboarding)
            if accelerated
            else _x4c_gpt2_rebuild_valid(row["rebuild"], onboarding)
        )
        and row["rebuild_roots"]
        == [durable["root_hex"] for durable in onboarding["durable"]]
        and row["rebuild_roots_equal_onboarding"] is True
        and row["rebuild_parallel_tasks"] == (1 if accelerated else 5)
        and row["warmup_count"] == 1
        and row["measured_count"] == 3
        and isinstance(row["candidates"], list)
        and len(row["candidates"]) == 4
    ):
        return False
    epoch_base = row["candidates"][0].get("epoch")
    if not _x4c_positive_int(epoch_base):
        return False
    for ordinal, candidate in enumerate(row["candidates"]):
        if not _x4c_gpt2_candidate_valid(
            candidate,
            role="warmup" if ordinal == 0 else f"measured-{ordinal}",
            ordinal=ordinal,
            measured=ordinal != 0,
            epoch_base=epoch_base,
            model_sub_correlations=row["model_sub_correlations"],
            model_full_correlations=row["model_full_correlations"],
            accelerated=accelerated,
        ):
            return False
        if accelerated and not _x4c_gpt2_candidate_gate_audit_valid(
            candidate.get("gate_audit")
        ):
            return False
    measured = row["candidates"][1:]
    medians = {
        "selected_upper_median_open_wall_s": "open_wall_s",
        "selected_upper_median_verify_wall_s": "verify_wall_s",
        "selected_upper_median_proof_ready_wall_s": "proof_ready_wall_s",
        "selected_upper_median_session_reusable_wall_s": "session_reusable_wall_s",
        "selected_upper_median_complete_e2e_wall_s": "complete_e2e_wall_s",
    }
    if any(
        row[output] != sorted(candidate[source] for candidate in measured)[1]
        for output, source in medians.items()
    ):
        return False
    open_pass = row["selected_upper_median_open_wall_s"] <= row["open_ceiling_s"]
    verify_pass = row["selected_upper_median_verify_wall_s"] <= row["verify_ceiling_s"]
    return (
        row["open_ceiling_s"] == 1.50
        and row["verify_ceiling_s"] == 0.25
        and row["open_pass"] is open_pass is True
        and row["verify_pass"] is verify_pass is True
        and isinstance(row["pinned_pool_release_wall_s"], (int, float))
        and not isinstance(row["pinned_pool_release_wall_s"], bool)
        and row["pinned_pool_release_wall_s"] >= 0
        and row["pinned_pool_release_restored_ownership"] is True
        and row["pcs_bytes"] == X4_V4_PCS_BYTES
        and row["response_bytes"] == X4_V4_RESPONSE_BYTES
        and row["rate"] == "1/8"
        and row["query_count"] == 111
        and row["all_candidates_accepted"] is True
        and row["zero_response_staging"] is True
        and row["exact_communication"] is True
        and row["diagnostic_comparisons"] == 1_592
        and row["diagnostic_soundness_credit_bits"] == 0
        and row["protocol_or_parameter_change"] is False
        and row["root_or_proof_format_change"] is False
        and row["lean_or_soundness_change"] is False
        and row["overall_pass"] is True
    )


def validate_x4c_gpt2_online_result(path: Path, onboarding_path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        if not onboarding_path.is_absolute():
            onboarding_path = REPO / onboarding_path
        onboarding_bytes = onboarding_path.read_bytes()
        onboarding = json.loads(onboarding_bytes)
        online = json.loads(path.read_bytes())
        return _x4c_gpt2_online_valid(
            online, onboarding, hashlib.sha256(onboarding_bytes).hexdigest()
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def validate_x4c_gpt2_accelerated_online_result(
    path: Path, onboarding_path: Path
) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        if not onboarding_path.is_absolute():
            onboarding_path = REPO / onboarding_path
        onboarding_bytes = onboarding_path.read_bytes()
        onboarding = json.loads(onboarding_bytes)
        online = json.loads(path.read_bytes())
        return _x4c_gpt2_online_valid(
            online,
            onboarding,
            hashlib.sha256(onboarding_bytes).hexdigest(),
            accelerated=True,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def validate_x4c_gpt2_v3_accelerated_online_result(
    path: Path, onboarding_path: Path, rebuild_admission_path: Path
) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        if not onboarding_path.is_absolute():
            onboarding_path = REPO / onboarding_path
        if not rebuild_admission_path.is_absolute():
            rebuild_admission_path = REPO / rebuild_admission_path
        onboarding_bytes = onboarding_path.read_bytes()
        rebuild_admission_bytes = rebuild_admission_path.read_bytes()
        onboarding = json.loads(onboarding_bytes)
        online = json.loads(path.read_bytes())
        rebuild_admission = json.loads(rebuild_admission_bytes)
        return _x4c_gpt2_online_valid(
            online,
            onboarding,
            hashlib.sha256(onboarding_bytes).hexdigest(),
            accelerated=True,
            schema=3,
            rebuild_admission=rebuild_admission,
            rebuild_admission_sha256=hashlib.sha256(
                rebuild_admission_bytes
            ).hexdigest(),
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _clean_validator_provenance() -> tuple[str, str]:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise ValueError("validation receipt requires a clean Git tree")
    git_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not _x4c_hex(git_sha, 40):
        raise ValueError("validator Git SHA is malformed")
    implementation_sha256 = hashlib.sha256(
        (REPO / "scripts" / "report.py").read_bytes()
    ).hexdigest()
    return git_sha, implementation_sha256


def write_x4c_gpt2_v3_validation_receipt(
    online_path: Path,
    onboarding_path: Path,
    rebuild_admission_path: Path,
    receipt_path: Path,
) -> Path:
    online_path = online_path if online_path.is_absolute() else REPO / online_path
    onboarding_path = (
        onboarding_path
        if onboarding_path.is_absolute()
        else REPO / onboarding_path
    )
    rebuild_admission_path = (
        rebuild_admission_path
        if rebuild_admission_path.is_absolute()
        else REPO / rebuild_admission_path
    )
    receipt_path = receipt_path if receipt_path.is_absolute() else REPO / receipt_path
    if not validate_x4c_gpt2_v3_accelerated_online_result(
        online_path, onboarding_path, rebuild_admission_path
    ):
        raise ValueError("schema-3 accelerated chain is not valid")
    online_bytes = online_path.read_bytes()
    onboarding_bytes = onboarding_path.read_bytes()
    rebuild_admission_bytes = rebuild_admission_path.read_bytes()
    online = json.loads(online_bytes)
    validator_git_sha, validator_implementation_sha256 = (
        _clean_validator_provenance()
    )
    receipt = {
        "schema": 1,
        "milestone": X4C_SCHEMA3_VALIDATION_RECEIPT_MILESTONE,
        "ruleset": X4C_SCHEMA3_VALIDATOR_RULESET,
        "online_sha256": hashlib.sha256(online_bytes).hexdigest(),
        "onboarding_sha256": hashlib.sha256(onboarding_bytes).hexdigest(),
        "rebuild_admission_sha256": hashlib.sha256(
            rebuild_admission_bytes
        ).hexdigest(),
        "crypto_build_id_scheme": online["crypto_build_id_scheme"],
        "crypto_build_id": online["crypto_build_id"],
        "validator_git_sha": validator_git_sha,
        "validator_git_dirty": False,
        "validator_implementation_sha256": validator_implementation_sha256,
        "validated_at_utc": _dt.datetime.now(_dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "overall_pass": True,
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    with receipt_path.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return receipt_path


def _x4c_rebuild_preflight_census_valid(row: Any) -> bool:
    integer_keys = (
        "directory_count",
        "file_count",
        "symlink_count",
        "byte_count",
    )
    return (
        _x4c_has(row, ("root_exists", "structural_blake3", *integer_keys))
        and isinstance(row["root_exists"], bool)
        and all(_x4c_nonnegative_int(row[key]) for key in integer_keys)
        and _x4c_hex(row["structural_blake3"], 64)
    )


def _x4c_rebuild_preflight_geometry(
    cohort_id: int,
    outer_log2: int,
    structural_slots: int,
    present_slots: int,
    *,
    oracle_kind: str,
    production: bool,
) -> dict[str, Any]:
    outer_len = 1 << outer_log2
    coefficient_bytes = present_slots * outer_len * 2
    host_oracle_bytes = present_slots * outer_len * 16
    host_outer_cache_bytes = (outer_len - 1) * 32
    return {
        "contract": "x4c-deterministic-production-geometry-v1",
        "descriptor_layout": "deterministic-prefix-present",
        "cohort_id": cohort_id,
        "oracle_kind": oracle_kind,
        "outer_log2": outer_log2,
        "outer_len": outer_len,
        "structural_slots": structural_slots,
        "present_slots": present_slots,
        "coefficient_bytes": coefficient_bytes,
        "host_oracle_bytes": host_oracle_bytes,
        "host_outer_cache_bytes": host_outer_cache_bytes,
        "final_resident_host_bytes": (
            coefficient_bytes + host_oracle_bytes + host_outer_cache_bytes
        ),
        "estimated_rebuild_peak_bytes": (
            coefficient_bytes + host_oracle_bytes + outer_len * 48
        ),
        "estimated_device_working_set_bytes": max(
            outer_len * 40, 512 * 1024 * 1024
        ),
        "production_geometry": production,
    }


_X4C_REBUILD_PREFLIGHT_STAGES = {
    "synthetic-small": _x4c_rebuild_preflight_geometry(
        0xA5FF0001,
        12,
        4,
        3,
        oracle_kind="weight-extension",
        production=False,
    ),
    "aux-ell16": _x4c_rebuild_preflight_geometry(
        0xA5000101,
        19,
        64,
        49,
        oracle_kind="auxiliary",
        production=True,
    ),
    "aux-ell17": _x4c_rebuild_preflight_geometry(
        0xA5000100,
        20,
        2,
        2,
        oracle_kind="auxiliary",
        production=True,
    ),
    "mu20": _x4c_rebuild_preflight_geometry(
        0xA5000003,
        24,
        16,
        13,
        oracle_kind="weight-extension",
        production=True,
    ),
}


def _x4c_rebuild_preflight_common_valid(row: Any) -> bool:
    return (
        _x4c_has(
            row,
            (
                "schema",
                "milestone",
                "git_sha",
                "git_dirty",
                "profile",
                "protocol",
                "design_sha256",
                "stage",
                "manual_single_stage",
                "next_stage_launched",
                "production_gate_credit",
                "durable_census_before",
                "durable_census_after",
                "durable_census_stable",
                "accepted",
            ),
        )
        and row["schema"] == 2
        and row["milestone"] == X4C_GPT2_REBUILD_PREFLIGHT_MILESTONE
        and _x4c_hex(row["git_sha"], 40)
        and row["git_dirty"] is False
        and row["profile"] == X4C_POD_PROFILE
        and row["protocol"] == X4C_GPT2_PROTOCOL
        and row["design_sha256"] == X4C_V1_DESIGN_SHA256
        and row["manual_single_stage"] is True
        and row["next_stage_launched"] is False
        and row["production_gate_credit"] is False
        and _x4c_rebuild_preflight_census_valid(row["durable_census_before"])
        and row["durable_census_after"] == row["durable_census_before"]
        and row["durable_census_stable"] is True
        and row["accepted"] is True
    )


def _x4c_rebuild_preflight_stage_valid(row: Any) -> bool:
    stage = row.get("stage")
    expected = _X4C_REBUILD_PREFLIGHT_STAGES.get(stage)
    if expected is None:
        return False
    required = (
        "automatic_cpu_fallback",
        "fixture",
        "host_memory_preflight",
        "cuda_memory_preflight",
        "fixture_generation_wall_s",
        "cpu_reference_wall_s",
        "cpu_reference_root",
        "cuda_rebuild_root",
        "root_reference_equality",
        "rebuild",
        "logical_rebuild_bytes",
        "logical_bytes_per_second",
        "final_process_memory",
        "scratch_files_created",
        "scratch_bytes_read",
        "scratch_bytes_written",
        "abort_reasons",
    )
    host = row.get("host_memory_preflight")
    cuda = row.get("cuda_memory_preflight")
    logical = expected["final_resident_host_bytes"]
    cohort_expected = (
        expected["cohort_id"],
        expected["coefficient_bytes"],
        expected["host_outer_cache_bytes"],
    )
    return (
        _x4c_rebuild_preflight_common_valid(row)
        and _x4c_has(row, required)
        and row["automatic_cpu_fallback"] is False
        and row["fixture"] == expected
        and _x4c_has(
            host,
            (
                "mem_available_bytes",
                "estimated_rebuild_peak_bytes",
                "sufficient",
            ),
        )
        and _x4c_positive_int(host["mem_available_bytes"])
        and host["estimated_rebuild_peak_bytes"]
        == expected["estimated_rebuild_peak_bytes"]
        and host["mem_available_bytes"] >= host["estimated_rebuild_peak_bytes"]
        and host["sufficient"] is True
        and _x4c_has(
            cuda,
            (
                "free_bytes",
                "total_bytes",
                "estimated_working_set_bytes",
                "sufficient",
            ),
        )
        and _x4c_positive_int(cuda["free_bytes"])
        and _x4c_positive_int(cuda["total_bytes"])
        and cuda["total_bytes"] >= cuda["free_bytes"]
        and cuda["estimated_working_set_bytes"]
        == expected["estimated_device_working_set_bytes"]
        and cuda["free_bytes"] >= cuda["estimated_working_set_bytes"]
        and cuda["sufficient"] is True
        and all(
            isinstance(row[key], (int, float))
            and not isinstance(row[key], bool)
            and row[key] > 0
            for key in ("fixture_generation_wall_s", "cpu_reference_wall_s")
        )
        and _x4c_hex(row["cpu_reference_root"], 64)
        and row["cuda_rebuild_root"] == row["cpu_reference_root"]
        and row["root_reference_equality"] is True
        and _x4c_gpt2_accelerated_cohort_valid(
            row["rebuild"], cohort_expected
        )
        and row["logical_rebuild_bytes"] == logical
        and isinstance(row["logical_bytes_per_second"], (int, float))
        and not isinstance(row["logical_bytes_per_second"], bool)
        and row["logical_bytes_per_second"] > 0
        and abs(
            row["logical_bytes_per_second"]
            - logical / row["rebuild"]["wall_s"]
        )
        <= max(1e-9, row["logical_bytes_per_second"] * 1e-12)
        and _x4c_gpt2_process_memory_valid(row["final_process_memory"])
        and row["scratch_files_created"] == 0
        and row["scratch_bytes_read"] == 0
        and row["scratch_bytes_written"] == 0
        and row["abort_reasons"] == []
    )


def _x4c_rebuild_projection_valid(row: Any) -> bool:
    required = (
        "source_stages",
        "source_record_blake3",
        "conservative_floor_logical_bytes_per_second",
        "targets",
        "decision_only",
    )
    expected_source_stages = ["aux-ell16", "aux-ell17", "mu20"]
    mu22 = _x4c_rebuild_preflight_geometry(
        0xA5000002,
        26,
        64,
        36,
        oracle_kind="weight-extension",
        production=True,
    )
    mu26 = _x4c_rebuild_preflight_geometry(
        0xA5000001,
        30,
        2,
        2,
        oracle_kind="weight-extension",
        production=True,
    )
    if not (
        _x4c_rebuild_preflight_common_valid(row)
        and row.get("stage") == "project"
        and _x4c_has(row, required)
        and row["source_stages"] == expected_source_stages
        and isinstance(row["source_record_blake3"], list)
        and len(row["source_record_blake3"]) == 3
        and all(_x4c_hex(digest, 64) for digest in row["source_record_blake3"])
        and isinstance(
            row["conservative_floor_logical_bytes_per_second"], (int, float)
        )
        and not isinstance(
            row["conservative_floor_logical_bytes_per_second"], bool
        )
        and row["conservative_floor_logical_bytes_per_second"] > 0
        and isinstance(row["targets"], list)
        and len(row["targets"]) == 2
        and row["decision_only"] is True
    ):
        return False
    floor = row["conservative_floor_logical_bytes_per_second"]
    for target, name, expected in zip(
        row["targets"], ("mu22", "mu26"), (mu22, mu26), strict=True
    ):
        expected_fields = {
            "cohort_id": expected["cohort_id"],
            "name": name,
            "coefficient_bytes": expected["coefficient_bytes"],
            "host_oracle_bytes": expected["host_oracle_bytes"],
            "host_outer_cache_bytes": expected["host_outer_cache_bytes"],
            "final_resident_host_bytes": expected["final_resident_host_bytes"],
            "estimated_rebuild_peak_bytes": expected[
                "estimated_rebuild_peak_bytes"
            ],
            "estimated_device_working_set_bytes": expected[
                "estimated_device_working_set_bytes"
            ],
        }
        if not (
            isinstance(target, dict)
            and all(target.get(key) == value for key, value in expected_fields.items())
            and isinstance(target.get("projected_wall_s"), (int, float))
            and not isinstance(target["projected_wall_s"], bool)
            and target["projected_wall_s"] > 0
            and abs(
                target["projected_wall_s"]
                - expected["final_resident_host_bytes"] / floor
            )
            <= max(1e-9, target["projected_wall_s"] * 1e-12)
        ):
            return False
    return True


def validate_x4c_rebuild_preflight_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        row = json.loads(path.read_bytes())
        return (
            _x4c_rebuild_projection_valid(row)
            if row.get("stage") == "project"
            else _x4c_rebuild_preflight_stage_valid(row)
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4c_probe_candidate_valid(
    candidate: Any,
    *,
    variant: str,
    measured: bool,
    geometry: dict[str, Any],
) -> bool:
    if not (
        isinstance(candidate, dict)
        and candidate.get("variant") == variant
        and candidate.get("measured") is measured
        and _x4c_nonnegative_int(candidate.get("ordinal"))
        and _x4c_positive_int(candidate.get("child_pid"))
        and candidate.get("geometry") == geometry
        and candidate.get("populated_bytes") == geometry["populated_bytes"]
        and _x4c_positive_int(candidate.get("touched_pages"))
        and _x4c_positive_int(candidate.get("population_checksum_u64"))
        and _x4c_boundary_timeline_valid(candidate.get("boundaries"))
        and candidate.get("child_exit_success") is True
        and candidate.get("child_exit_code") == 0
        and candidate.get("accepted") is True
        and candidate.get("obstruction_reasons") == []
    ):
        return False
    timing = candidate.get("timing")
    if not (
        isinstance(timing, dict)
        and _x4c_positive_int(timing.get("allocation_population_wall_ns"))
        and _x4c_positive_int(timing.get("proof_ready_wall_ns"))
        and _x4c_positive_int(timing.get("parent_child_wall_ns"))
        and _x4c_nonnegative_int(timing.get("child_reap_wall_ns"))
        and all(
            _x4c_nonnegative_int(timing.get(key))
            for key in (
                "distributed_drop_wall_ns",
                "destroy_codewords_wall_ns",
                "destroy_outer_cache_levels_wall_ns",
                "destroy_remaining_state_wall_ns",
                "logical_arena_reset_wall_ns",
                "backing_release_wall_ns",
                "teardown_total_wall_ns",
            )
        )
    ):
        return False
    boundaries = {boundary["label"]: boundary for boundary in candidate["boundaries"]}
    populated = boundaries.get("payload_populated") or boundaries.get(
        "payload_populated_no_teardown"
    )
    if not (
        isinstance(populated, dict)
        and populated["sealed_ownership"]["fold_codeword_bytes"]
        == geometry["fold_codeword_bytes"]
        and populated["sealed_ownership"]["fold_outer_cache_bytes"]
        == geometry["fold_outer_cache_bytes"]
        and populated["sealed_ownership"]["ordinary_host_bytes"]
        == geometry["populated_bytes"]
        and populated["sealed_ownership"]["pinned_host_bytes"] == 0
        and populated["sealed_ownership"]["device_bytes"] == 0
        and populated["sealed_ownership"]["file_backed_bytes"] == 0
        and all(
            boundary["temporary_files"]["live_file_count"] == 0
            and boundary["temporary_files"]["live_file_bytes"] == 0
            and boundary["temporary_files"]["live_directory_count"] == 0
            for boundary in candidate["boundaries"]
        )
    ):
        return False

    final = candidate["boundaries"][-1]["sealed_ownership"]
    if variant == "distributed_drop":
        return (
            candidate.get("termination") == "normal_return_after_explicit_teardown"
            and timing["distributed_drop_wall_ns"] > 0
            and timing["teardown_total_wall_ns"] > 0
            and _x4c_positive_int(timing.get("session_reusable_wall_ns"))
            and candidate.get("intentionally_retained_bytes") == 0
            and candidate.get("arena_backing_retained_after_reset_bytes") == 0
            and candidate.get("outstanding_payload_bytes_after_teardown") == 0
            and final["ordinary_host_bytes"] == 0
        )
    if variant == "manually_drop_no_teardown":
        return (
            candidate.get("termination") == "_exit_no_destructors"
            and timing["teardown_total_wall_ns"] == 0
            and timing.get("session_reusable_wall_ns") is None
            and candidate.get("intentionally_retained_bytes")
            == geometry["populated_bytes"]
            and candidate.get("outstanding_payload_bytes_after_teardown")
            == geometry["populated_bytes"]
            and final["ordinary_host_bytes"] == geometry["populated_bytes"]
        )
    if variant == "categorized_drop":
        codewords = boundaries.get("codewords_destroyed")
        cache = boundaries.get("outer_cache_levels_destroyed")
        remaining = boundaries.get("remaining_state_destroyed")
        return (
            candidate.get("termination") == "normal_return_after_explicit_teardown"
            and timing["destroy_codewords_wall_ns"] > 0
            and timing["destroy_outer_cache_levels_wall_ns"] > 0
            and timing["destroy_remaining_state_wall_ns"] > 0
            and timing["teardown_total_wall_ns"] > 0
            and _x4c_positive_int(timing.get("session_reusable_wall_ns"))
            and isinstance(codewords, dict)
            and codewords["sealed_ownership"]["fold_codeword_bytes"] == 0
            and codewords["sealed_ownership"]["fold_outer_cache_bytes"]
            == geometry["fold_outer_cache_bytes"]
            and isinstance(cache, dict)
            and cache["sealed_ownership"]["ordinary_host_bytes"] == 0
            and isinstance(remaining, dict)
            and remaining["sealed_ownership"]["ordinary_host_bytes"] == 0
            and candidate.get("outstanding_payload_bytes_after_teardown") == 0
            and final["ordinary_host_bytes"] == 0
        )
    if variant == "single_arena_reset":
        reset = boundaries.get("arena_logically_reset_backing_retained")
        release = boundaries.get("arena_backing_released")
        return (
            candidate.get("termination") == "normal_return_after_explicit_teardown"
            and timing["logical_arena_reset_wall_ns"] > 0
            and timing["backing_release_wall_ns"] > 0
            and timing["teardown_total_wall_ns"] > 0
            and _x4c_positive_int(timing.get("session_reusable_wall_ns"))
            and candidate.get("arena_backing_retained_after_reset_bytes")
            == geometry["populated_bytes"]
            and isinstance(reset, dict)
            and reset["sealed_ownership"]["fold_codeword_bytes"] == 0
            and reset["sealed_ownership"]["fold_outer_cache_bytes"] == 0
            and reset["sealed_ownership"]["other_ordinary_host_bytes"]
            == geometry["populated_bytes"]
            and isinstance(release, dict)
            and release["sealed_ownership"]["ordinary_host_bytes"] == 0
            and candidate.get("outstanding_payload_bytes_after_teardown") == 0
            and final["ordinary_host_bytes"] == 0
        )
    return False


def _x4c_lifecycle_probe_result_valid(row: dict[str, Any]) -> bool:
    geometry = row.get("geometry")
    variants = row.get("variants")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == X4C_LIFECYCLE_PROBE_MILESTONE
        and row.get("phase") == 2
        and row.get("pod_profile") == X4C_POD_PROFILE
        and row.get("mode") == "exact_pod"
        and row.get("pod_contacted") is True
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and _x4c_immutable_valid(row.get("immutable"))
        and _x4c_storage_and_machine_valid(row.get("machine"))
        and isinstance(geometry, dict)
        and geometry.get("domain_log2") == 29
        and geometry.get("fold_rounds") == 27
        and geometry.get("fold_codeword_bytes")
        == X4C_PRODUCTION_FOLD_CODEWORD_BYTES
        and geometry.get("fold_outer_cache_bytes")
        == X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
        and geometry.get("populated_bytes") == X4C_PRODUCTION_SEALED_STATE_BYTES
        and row.get("warmup_count_per_variant") == 1
        and _x4c_positive_int(row.get("measured_candidates_per_variant"))
        and row["measured_candidates_per_variant"] >= 3
        and row.get("child_process_isolation") is True
        and isinstance(variants, list)
        and [variant.get("variant") for variant in variants if isinstance(variant, dict)]
        == [
            "distributed_drop",
            "manually_drop_no_teardown",
            "categorized_drop",
            "single_arena_reset",
        ]
    ):
        return False

    all_pids: set[int] = set()
    for variant in variants:
        name = variant["variant"]
        warmup = variant.get("warmup")
        measured = variant.get("measured_candidates")
        if not (
            variant.get("warmup_count") == 1
            and variant.get("measured_candidate_count")
            == row["measured_candidates_per_variant"]
            and isinstance(measured, list)
            and len(measured) == row["measured_candidates_per_variant"]
            and _x4c_probe_candidate_valid(
                warmup, variant=name, measured=False, geometry=geometry
            )
            and all(
                _x4c_probe_candidate_valid(
                    candidate, variant=name, measured=True, geometry=geometry
                )
                for candidate in measured
            )
            and [candidate["ordinal"] for candidate in measured]
            == list(range(1, len(measured) + 1))
            and variant.get("all_accepted") is True
        ):
            return False
        pids = [warmup["child_pid"], *[candidate["child_pid"] for candidate in measured]]
        if len(set(pids)) != len(pids) or any(pid in all_pids for pid in pids):
            return False
        all_pids.update(pids)
        ordered = sorted(measured, key=lambda candidate: candidate["timing"]["parent_child_wall_ns"])
        selected = ordered[len(ordered) // 2]
        if variant.get("selected_upper_median_ordinal") != selected["ordinal"]:
            return False
    return (
        row.get("all_accepted") is True
        and row.get("hard_stop_before_x4c_online") is True
    )


def validate_x4c_lifecycle_probe_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        with path.open("r", encoding="utf-8") as handle:
            return _x4c_lifecycle_probe_result_valid(json.load(handle))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def p6_shape(data: dict[str, Any]) -> bool:
    return (
        data.get("milestone") == "P6"
        and data.get("accepted") is True
        and data.get("t_prefill") == 100
        and data.get("n_decode") == 50
    )


def select_p6_record(results: list[dict[str, Any]]) -> dict[str, Any]:
    clean = [r for r in results if p6_shape(r) and not r.get("git_dirty", True)]
    if clean:
        return max(clean, key=lambda r: r["_mtime"])
    dirty = [r for r in results if p6_shape(r)]
    if dirty:
        return max(dirty, key=lambda r: r["_mtime"])
    raise SystemExit("no accepted P6 result for prompt 100 + decode 50")


def _c1_record_valid(row: dict[str, Any]) -> bool:
    reuse = row.get("c1_identity_seam_reuse")
    labels = row.get("comm_response_by_label")
    return (
        row.get("report_schema_version") == C1_REPORT_SCHEMA_VERSION
        and row.get("milestone") == "C1"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("chunked_accepted") is True
        and row.get("gate_flat_cost_per_token") is True
        and row.get("comm_response_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(labels, dict)
        and labels.get("auth_corrections") == C1_AUTH_CORRECTION_REFERENCE_BYTES
        and row.get("pcs_opening_bytes_total") == C1_PCS_OPENING_REFERENCE_BYTES
        and row.get("public_logits_packed_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes")
        == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 200
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("corr_sub_corrs") == C1_SUB_CORR_REFERENCE
        and row.get("corr_full_corrs") == C1_FULL_CORR_REFERENCE
        and row.get("pcg_backend") == "mock"
        and row.get("pcg_production_ready") is False
        and row.get("pcg_setup_comm_bytes") == 0
        and isinstance(reuse, dict)
        and reuse.get("identity_seam_alias_values") == C1_IDENTITY_SEAM_ALIAS_VALUES
        and reuse.get("saved_response_bytes")
        == P7B_PACKED_RESPONSE_REFERENCE_BYTES - C1_PACKED_RESPONSE_REFERENCE_BYTES
        and reuse.get("measured_transcript_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and reuse.get("measured_auth_correction_bytes")
        == C1_AUTH_CORRECTION_REFERENCE_BYTES
        and reuse.get("measured_packed_response_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and reuse.get("measured_prover_sub_corrs") == C1_SUB_CORR_REFERENCE
        and reuse.get("measured_verifier_sub_corrs") == C1_SUB_CORR_REFERENCE
        and reuse.get("measured_prover_full_corrs") == C1_FULL_CORR_REFERENCE
        and reuse.get("measured_verifier_full_corrs") == C1_FULL_CORR_REFERENCE
        and reuse.get("full_corrs_unchanged") is True
        and reuse.get("pcs_parameters_unchanged") is True
        and reuse.get("claims_unchanged") is True
        and reuse.get("byte_formulas_reconcile") is True
        and reuse.get("counters_reconcile") is True
        and reuse.get("typed_correlation_lanes") == 0
        and reuse.get("second_phase_b_shard_required") is False
    )


def select_c1_record(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    rows = [row for row in results if row.get("milestone") == "C1"]
    if not rows:
        return None
    valid = [row for row in rows if _c1_record_valid(row)]
    if not valid:
        raise SystemExit("C1 result exists but does not satisfy the registered reference")
    return max(valid, key=lambda row: row["_mtime"])


def select_packed_source(results: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any] | None:
    same_shape = [
        r
        for r in results
        if p6_shape(r)
        and r.get("t_prefill") == baseline.get("t_prefill")
        and r.get("n_decode") == baseline.get("n_decode")
        and "public_logits_packed_bytes" in r
    ]
    return max(same_shape, key=lambda r: r["_mtime"]) if same_shape else None


def msg_len(params: dict[str, int]) -> int:
    return params["cols"] + params["pad"]


def rate(params: dict[str, int]) -> float:
    return msg_len(params) / float(1 << params["code_bits"])


def distance(params: dict[str, int]) -> float:
    return 1.0 - rate(params)


def query_error_bits(params: dict[str, int]) -> float:
    base = 1.0 - distance(params) / 2.0
    return -params["n_queries"] * math.log2(base)


def queries_for_bits(params: dict[str, int], bits: float) -> int:
    base = 1.0 - distance(params) / 2.0
    return math.ceil(bits / -math.log2(base))


def multi_open_breakdown(params: dict[str, int], n_claims: int) -> dict[str, int]:
    rows = params["rows"]
    code_bits = params["code_bits"]
    q = params["n_queries"]
    masks = n_claims + 1
    u_vectors = 16 * msg_len(params) * masks
    corr_ss = 16 * n_claims
    zero_batch = 32  # mask_corr + m_z
    column_indices = 4 * q
    data_columns = 8 * rows * q
    mask_columns = 16 * masks * q
    merkle_paths = 32 * (code_bits + code_bits) * q
    columns = column_indices + data_columns + mask_columns + merkle_paths
    total = 32 + u_vectors + corr_ss + zero_batch + columns
    cached_query_cut = data_columns + 32 * code_bits * q
    return {
        "mask_root": 32,
        "u_vectors": u_vectors,
        "corr_ss": corr_ss,
        "zero_batch": zero_batch,
        "column_indices": column_indices,
        "data_columns": data_columns,
        "mask_columns": mask_columns,
        "merkle_paths": merkle_paths,
        "columns_total": columns,
        "cached_query_cut_bytes": cached_query_cut,
        "total": total,
    }


def with_queries(params: dict[str, int], n_queries: int) -> dict[str, int]:
    out = dict(params)
    out["n_queries"] = n_queries
    return out


def embed_pow2_shape(rows: int) -> dict[str, int]:
    total = 1 << 27
    assert total % rows == 0
    cols = total // rows
    msg = cols + EMBED_PARAMS["pad"]
    return {
        "rows": rows,
        "cols": cols,
        "pad": EMBED_PARAMS["pad"],
        "code_bits": (msg - 1).bit_length(),
        "n_queries": EMBED_PARAMS["n_queries"],
    }


def pcs_total(layer_params: dict[str, int], layer_claims: int, embed_params: dict[str, int], embed_claims: int) -> int:
    return (
        12 * multi_open_breakdown(layer_params, layer_claims)["total"]
        + multi_open_breakdown(embed_params, embed_claims)["total"]
    )


def pcs_cached_total(
    layer_params: dict[str, int],
    layer_claims: int,
    embed_params: dict[str, int],
    embed_claims: int,
) -> int:
    layer = multi_open_breakdown(layer_params, layer_claims)
    embed = multi_open_breakdown(embed_params, embed_claims)
    return 12 * (layer["total"] - layer["cached_query_cut_bytes"]) + (
        embed["total"] - embed["cached_query_cut_bytes"]
    )


def response_total(current_packed: int, current_pcs: int, new_pcs: int) -> int:
    return current_packed - current_pcs + new_pcs


def mb(x: float) -> float:
    return x / 1_000_000.0


def pcs_scenarios(baseline: dict[str, Any], current_packed_download: int) -> list[dict[str, Any]]:
    current_pcs = int(baseline["pcs_opening_bytes_total"])
    q60 = queries_for_bits(LAYER_PARAMS, 60.0)
    layer_q60 = with_queries(LAYER_PARAMS, q60)
    embed_q60 = with_queries(EMBED_PARAMS, q60)
    embed_4096 = embed_pow2_shape(1 << 12)

    rows = [
        (
            "current",
            "measured shape and claims",
            pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "implemented",
            None,
        ),
        (
            "q60_same_rate",
            f"projection only: Q={q60}, same rate/distance, >=60-bit query error",
            pcs_total(layer_q60, 8, embed_q60, 6),
            "soundness-decision-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "per_tensor_rlc",
            "projection only: layer claims 8->4, embed claims 6->3",
            pcs_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "protocol-design-required",
            None,
        ),
        (
            "q60_plus_rlc",
            f"projection only: Q={q60} plus per-tensor RLC",
            pcs_total(layer_q60, 4, embed_q60, 3),
            "soundness-and-protocol-design-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "embed_4096_rows",
            "projection only: embed rows=2^12, cols=2^15, code_bits=16",
            pcs_total(LAYER_PARAMS, 8, embed_4096, 6),
            "layout-variant-required",
            {"embed_params": embed_4096, "embed_error_bits": query_error_bits(embed_4096)},
        ),
        (
            "static_query_cache_marginal",
            "projection only: verifier caches data columns and their Merkle paths after setup",
            pcs_cached_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "stateful-verifier-design-required",
            None,
        ),
        (
            "static_query_cache_plus_rlc_marginal",
            "projection only: static query cache plus per-tensor RLC",
            pcs_cached_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "stateful-verifier-and-protocol-design-required",
            None,
        ),
    ]

    out = []
    for name, note, pcs_bytes, status, extra in rows:
        row = {
            "name": name,
            "status": status,
            "note": note,
            "pcs_opening_bytes": pcs_bytes,
            "pcs_delta_bytes": pcs_bytes - current_pcs,
            "packed_response_download_bytes": response_total(current_packed_download, current_pcs, pcs_bytes),
        }
        if extra:
            row.update(extra)
        out.append(row)
    return out


def rho_model(baseline: dict[str, Any]) -> dict[str, Any]:
    rho_prefill = float(baseline["rho_prefill"])
    rho_decode = float(baseline["rho_decode"])
    relative = [1.0, 2.0, 2.5, 3.0, 5.0, 8.0, 10.0]
    return {
        "definition": "predicted_gpu_rho = cpu_rho / relative_prover_vs_native_gpu_speedup",
        "targets": P7_RHO_TARGETS,
        "required_relative_prover_vs_native_speedup": {
            phase: rho / P7_RHO_TARGETS[phase]
            for phase, rho in (("prefill", rho_prefill), ("decode", rho_decode))
        },
        "sensitivity": [
            {
                "relative_prover_vs_native_speedup": r,
                "rho_prefill": rho_prefill / r,
                "rho_decode": rho_decode / r,
                "prefill_target_met": rho_prefill / r <= P7_RHO_TARGETS["prefill"],
                "decode_target_met": rho_decode / r <= P7_RHO_TARGETS["decode"],
            }
            for r in relative
        ],
    }


def summarize_rhos(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = [
        "rho_kernel_weighted_layer",
        "rho_blind_total",
        "rho",
        "rho_prefill",
        "rho_decode",
        "rho_cpu_prefill",
        "rho_cpu_decode",
    ]
    rows = []
    for r in results:
        vals = {k: r[k] for k in keys if k in r}
        if vals:
            rows.append(
                {
                    "source": r["_path"],
                    "milestone": r.get("milestone"),
                    "git_dirty": r.get("git_dirty"),
                    **vals,
                }
            )
    return rows


def measured_pcs_profiles(results: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    rows_by_shape: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    seen: set[str] = set()
    candidates = [baseline] + [
        r
        for r in results
        if r.get("accepted") is True
        and r.get("milestone")
        in {
            "P6",
            "P6-quick",
            "P7-integrated-hybrid",
            "P7-integrated-hybrid-quick",
            "P7-integrated-resident",
            "P7-integrated-resident-quick",
        }
        and "pcs_opening_bytes_total" in r
    ]
    for r in candidates:
        source = r["_path"]
        if source in seen:
            continue
        seen.add(source)
        n_queries = int(r.get("pcs_n_queries", 200))
        params = with_queries(LAYER_PARAMS, n_queries)
        packed = r.get("total_response_download_packed_bytes")
        if packed is None and "public_logits_packed_bytes" in r:
            packed = int(r["comm_response_bytes"]) + int(r["public_logits_packed_bytes"])
        row = {
            "_mtime": r["_mtime"],
            "source": source,
            "milestone": r.get("milestone"),
            "git_dirty": r.get("git_dirty"),
            "t_prefill": r.get("t_prefill"),
            "n_decode": r.get("n_decode"),
            "pcs_n_queries": n_queries,
            "pcs_query_error_bits": float(r.get("pcs_query_error_bits", query_error_bits(params))),
            "pcs_opening_bytes_total": int(r["pcs_opening_bytes_total"]),
            "pcs_cached_query_marginal_bytes_total": r.get("pcs_cached_query_marginal_bytes_total"),
            "comm_response_bytes": r.get("comm_response_bytes"),
            "total_response_download_packed_bytes": packed,
        }
        key = (row["milestone"], row["t_prefill"], row["n_decode"], row["pcs_n_queries"])
        prev = rows_by_shape.get(key)
        if prev is None or row["_mtime"] > prev["_mtime"]:
            rows_by_shape[key] = row
    rows = list(rows_by_shape.values())
    for row in rows:
        row.pop("_mtime", None)
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["pcs_n_queries"], x["source"]))
    return rows


def mock_pcg_lower_bounds(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-mock-pcg-lower-bound":
            continue
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_mock_expansion_s": r.get("t_total_mock_expansion_s"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_a(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-a":
            continue
        timings = r.get("phase_a_timings") or {}
        params = r.get("lpn_parameters") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "sub_equiv_corrs": (r.get("corr_sub_corrs") or 0)
                + 2 * (r.get("corr_full_corrs") or 0),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_real_expansion_s")
                ),
                "t_setup_stub_s": timings.get("t_setup_stub_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "sub_equiv_corrs_per_s_joint": r.get("sub_equiv_corrs_per_s_joint"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "lpn_parameters": params,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_b(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-b":
            continue
        timings = r.get("phase_b_timings") or {}
        setup = r.get("phase_b_setup") or {}
        comm = setup.get("comm") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "production_ready": r.get("production_ready"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "base_ot_bytes": comm.get("base_ot_bytes"),
                "ot_extension_bytes": comm.get("ot_extension_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_setup_and_expansion_s")
                ),
                "t_base_ot_s": timings.get("t_base_ot_s"),
                "t_ot_extension_s": timings.get("t_ot_extension_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "setup": setup,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def gpu_roofline_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-roofline", "P7-gpu-roofline-quick"}:
            continue
        kernel = r.get("kernel") or {}
        # Early remote-provider diagnostics had correct outputs but non-blocking
        # event timings (0 s / impossible bandwidth). Keep the raw JSON
        # append-only, but never promote it into the aggregate roofline profiles.
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        stream = kernel.get("stream") or {}
        chain = kernel.get("chain") or {}
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "stream_gpu_s": stream.get("gpu_s"),
                "stream_gpu_cpu_speedup": stream.get("gpu_cpu_speedup"),
                "stream_gpu_bandwidth_gb_s": stream.get("gpu_bandwidth_gb_s"),
                "chain_gpu_s": chain.get("gpu_s"),
                "chain_gpu_cpu_speedup": chain.get("gpu_cpu_speedup"),
                "chain_gpu_fp2_mul_s": chain.get("gpu_fp2_mul_s"),
                "screening": r.get("screening"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_fused_epilogue_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-fused-epilogue",
            "P7-gpu-fused-epilogue-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "weighted_rho_kernel": kernel.get("weighted_rho_kernel"),
                "gate_weighted_rho_le_1_30": kernel.get("gate_weighted_rho_le_1_30"),
                "shapes": kernel.get("shapes"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_tree_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-tree", "P7-gpu-logup-tree-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_layers_checksum": kernel.get("all_layers_checksum"),
                "operation_counts": kernel.get("operation_counts"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-rounds", "P7-gpu-logup-rounds-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_blind_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-logup-blind-rounds",
            "P7-gpu-logup-blind-rounds-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "blind_corrections_correct": kernel.get("blind_corrections_correct"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_blind_s": kernel.get("cpu_blind_s"),
                "gpu_blind_s": kernel.get("gpu_blind_s"),
                "gpu_clear_s": kernel.get("gpu_clear_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "blind_over_clear": kernel.get("blind_over_clear"),
                "gate_speedup_ge_5_48_and_overhead_le_1_05": kernel.get(
                    "gate_speedup_ge_5_48_and_overhead_le_1_05"
                ),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_pcs_arithmetic_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-pcs-arithmetic",
            "P7-gpu-pcs-arithmetic-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "gate_each_speedup_ge_5_48": kernel.get("gate_each_speedup_ge_5_48"),
                "ntt": kernel.get("ntt"),
                "combine_rows": kernel.get("combine_rows"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_blake3_merkle_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-blake3-merkle",
            "P7-gpu-blake3-merkle-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        rust = r.get("rust_reference") or {}
        if (
            not kernel.get("host_device_correctness")
            or not kernel.get("timing_sane")
            or not r.get("root_matches_rust_blake3")
        ):
            continue
        gpu_s = kernel.get("gpu_s")
        cpu_s = rust.get("cpu_s")
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "host_device_correctness": kernel.get("host_device_correctness"),
                "root_matches_rust_blake3": r.get("root_matches_rust_blake3"),
                "timing_sane": kernel.get("timing_sane"),
                "root": kernel.get("root"),
                "gpu_s": gpu_s,
                "rust_cpu_s": cpu_s,
                "gpu_cpu_speedup": cpu_s / gpu_s if cpu_s and gpu_s else None,
                "gate_gpu_s_le_0_075": kernel.get("gate_gpu_s_le_0_075"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_native_inference_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-native-inference",
            "P7-gpu-native-inference-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if (
            not r.get("correctness")
            or not r.get("golden_match")
            or not kernel.get("deterministic")
            or kernel.get("fixed_point_errors")
        ):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "baseline": r.get("baseline"),
                "correctness": r.get("correctness"),
                "golden_match": r.get("golden_match"),
                "parameters": kernel.get("parameters"),
                "prefill_s": kernel.get("prefill_s"),
                "decode_50_s": kernel.get("decode_50_s"),
                "prefill_timing": kernel.get("prefill_timing"),
                "decode_50_timing": kernel.get("decode_50_timing"),
                "memory": kernel.get("memory"),
                "prefill_argmax": kernel.get("prefill_argmax"),
                "native_gpu_speedup": r.get("native_gpu_speedup"),
                "report_schema_version": r.get("report_schema_version"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_accelerator_profiles(
    results: list[dict[str, Any]],
    milestones: set[str],
    backend: str,
    *,
    include_p7b_fields: bool = False,
) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in milestones:
            continue
        if not r.get("accepted") or r.get("accelerator_backend") != backend:
            continue
        cleanup_live = r.get("accelerator_live_device_bytes_after_cleanup")
        cleanup_workspace = r.get("accelerator_workspace_device_bytes_after_cleanup")
        cleanup_resident = r.get("accelerator_resident_device_bytes_after_cleanup")
        cleanup_cached = r.get("accelerator_cached_resident_device_bytes_after_cleanup")
        cleanup_values = (cleanup_live, cleanup_workspace, cleanup_resident, cleanup_cached)
        cleanup_accounting_ok = (
            None
            if any(value is None for value in cleanup_values)
            else cleanup_resident == 0
            and cleanup_live == cleanup_workspace + cleanup_cached
        )
        trimmed_live = r.get("accelerator_live_device_bytes_after_cache_trim")
        trimmed_workspace = r.get("accelerator_workspace_device_bytes_after_cache_trim")
        trimmed_resident = r.get("accelerator_resident_device_bytes_after_cache_trim")
        trimmed_cached = r.get("accelerator_cached_resident_device_bytes_after_cache_trim")
        trimmed_values = (trimmed_live, trimmed_workspace, trimmed_resident, trimmed_cached)
        cache_trim_accounting_ok = (
            None
            if any(value is None for value in trimmed_values)
            else trimmed_resident == 0 and trimmed_cached == 0 and trimmed_live == trimmed_workspace
        )
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "threads": r.get("threads"),
                "report_schema_version": r.get("report_schema_version"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "benchmark_warmup_repetitions": r.get("benchmark_warmup_repetitions"),
                "benchmark_repetitions": r.get("benchmark_repetitions"),
                "prove_prefill_s": r.get("t_prove_prefill_only_s"),
                "prove_response_s": r.get("t_prove_response_s"),
                "prove_decode_marginal_s": r.get("t_prove_decode_marginal_s"),
                "prover_online_accounted_response_s": r.get(
                    "t_prover_online_accounted_response_s"
                ),
                "prover_online_accounted_decode_marginal_s": r.get(
                    "t_prover_online_accounted_decode_marginal_s"
                ),
                "response_session_wall_s": r.get("t_response_session_wall_s"),
                "protocol_closure_exchange_s": r.get("t_protocol_closure_exchange_s"),
                "verifier_accounted_s": r.get("t_verifier_accounted_s"),
                "prove_prefill_timing": r.get("prove_prefill_timing"),
                "prove_response_timing": r.get("prove_response_timing"),
                "prove_decode_marginal_timing": r.get("prove_decode_marginal_timing"),
                "prover_online_accounted_response_timing": r.get(
                    "prover_online_accounted_response_timing"
                ),
                "prover_online_accounted_decode_marginal_timing": r.get(
                    "prover_online_accounted_decode_marginal_timing"
                ),
                "response_session_wall_timing": r.get("response_session_wall_timing"),
                "protocol_closure_exchange_timing": r.get(
                    "protocol_closure_exchange_timing"
                ),
                "verifier_accounted_timing": r.get("verifier_accounted_timing"),
                "cpu_relative_rho": {
                    "prefill": r.get("rho_cpu_prefill", r.get("rho_prefill")),
                    "decode": r.get("rho_cpu_decode", r.get("rho_decode")),
                },
                "rho_denominator": r.get("rho_denominator"),
                "golden_decode_checked": r.get("golden_decode_checked"),
                "golden_decode_match": r.get("golden_decode_match"),
                "flat_cost_last_over_first": r.get("curve_last_over_first"),
                "flat_cost_gate": r.get("gate_flat_cost_per_token"),
                "packed_response_bytes": r.get("total_response_download_packed_bytes"),
                "communication": {
                    "prefill_bytes": r.get("comm_prefill_bytes"),
                    "response_bytes": r.get("comm_response_bytes"),
                    "decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                    "pcs_opening_bytes": r.get("pcs_opening_bytes_total"),
                    "public_logits_packed_bytes": r.get("public_logits_packed_bytes"),
                    "response_by_label": r.get("comm_response_by_label"),
                    "pcs_by_label": r.get("comm_pcs_by_label"),
                },
                "pcs_commit_timing": r.get("pcs_commit_timing"),
                "pcs_open_timing": r.get("pcs_open_timing"),
                "pcs_verify_timing": r.get("pcs_verify_timing"),
                "verify_response_timing": r.get("verify_response_timing"),
                "scalar_closure_soundness": {
                    "prod_claims": r.get("closure_prod_claims"),
                    "zero_claims": r.get("closure_zero_claims"),
                    "prod_bits": r.get("closure_prod_scalar_soundness_bits"),
                    "zero_bits": r.get("closure_zero_scalar_soundness_bits"),
                    "union_bits": r.get("closure_union_scalar_soundness_bits"),
                },
                "accelerator_witness": r.get("accelerator_witness"),
                "accelerator_response_witness": r.get("accelerator_response_witness"),
                "accelerator_prefill": r.get("accelerator_prefill_proving"),
                "accelerator_session": r.get("accelerator_proving"),
                "accelerator_live_device_bytes_after_cleanup": r.get(
                    "accelerator_live_device_bytes_after_cleanup"
                ),
                "accelerator_workspace_device_bytes_after_cleanup": r.get(
                    "accelerator_workspace_device_bytes_after_cleanup"
                ),
                "accelerator_resident_device_bytes_after_cleanup": r.get(
                    "accelerator_resident_device_bytes_after_cleanup"
                ),
                "accelerator_cached_resident_device_bytes_after_cleanup": r.get(
                    "accelerator_cached_resident_device_bytes_after_cleanup"
                ),
                "accelerator_cleanup_memory_accounting_ok": cleanup_accounting_ok,
                "accelerator_live_device_bytes_after_cache_trim": trimmed_live,
                "accelerator_workspace_device_bytes_after_cache_trim": trimmed_workspace,
                "accelerator_resident_device_bytes_after_cache_trim": trimmed_resident,
                "accelerator_cached_resident_device_bytes_after_cache_trim": trimmed_cached,
                "accelerator_cache_trim_memory_accounting_ok": cache_trim_accounting_ok,
                "peak_rss_gb": r.get("peak_rss_gb"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "pcg_backend": r.get("pcg_backend"),
                "pcg_setup_comm_bytes": r.get("pcg_setup_comm_bytes"),
                "pcg_real_phase_a_total_s": r.get("pcg_real_phase_a_total_s"),
            }
        )
        if include_p7b_fields:
            rows[-1].update(
                {
                    "accepted": r.get("accepted"),
                    "accelerator_backend": r.get("accelerator_backend"),
                    "git_sha": r.get("git_sha"),
                    "git_sha_before_benchmark": r.get("git_sha_before_benchmark"),
                    "git_sha_before_serialization": r.get(
                        "git_sha_before_serialization"
                    ),
                    "git_dirty_before_benchmark": r.get("git_dirty_before_benchmark"),
                    "git_dirty_before_serialization": r.get(
                        "git_dirty_before_serialization"
                    ),
                    "accelerator_cuda_abi_version": r.get(
                        "accelerator_cuda_abi_version"
                    ),
                    "resident_timing_policy": r.get("resident_timing_policy"),
                    "p7b_gate_evaluated": r.get("p7b_gate_evaluated"),
                    "p7b_gate_profile": r.get("p7b_gate_profile"),
                    "p7b_machine_eligible": r.get("p7b_machine_eligible"),
                    "p7b_timing_statistic": r.get("p7b_timing_statistic"),
                    "p7b_counter_statistic": r.get("p7b_counter_statistic"),
                    "p7b_prefill_core_gate_s": r.get("p7b_prefill_core_gate_s"),
                    "p7b_decode_marginal_gate_s": r.get(
                        "p7b_decode_marginal_gate_s"
                    ),
                    "p7b_sync_count_gate_retired": r.get(
                        "p7b_sync_count_gate_retired"
                    ),
                    "p7b_sync_wall_fraction_gate": r.get(
                        "p7b_sync_wall_fraction_gate"
                    ),
                    "p7b_sync_wall_absolute_gate_s": r.get(
                        "p7b_sync_wall_absolute_gate_s"
                    ),
                    "p7b_h2d_gate_bytes": r.get("p7b_h2d_gate_bytes"),
                    "p7b_prefill_core_observed_s": r.get(
                        "p7b_prefill_core_observed_s"
                    ),
                    "p7b_decode_marginal_observed_s": r.get(
                        "p7b_decode_marginal_observed_s"
                    ),
                    "p7b_sync_observed": r.get("p7b_sync_observed"),
                    "p7b_sync_wall_fraction_observed": r.get(
                        "p7b_sync_wall_fraction_observed"
                    ),
                    "p7b_sync_wall_absolute_observed_s": r.get(
                        "p7b_sync_wall_absolute_observed_s"
                    ),
                    "p7b_h2d_observed_bytes": r.get("p7b_h2d_observed_bytes"),
                    "p7b_prefill_core_gate_pass": r.get(
                        "p7b_prefill_core_gate_pass"
                    ),
                    "p7b_decode_marginal_gate_pass": r.get(
                        "p7b_decode_marginal_gate_pass"
                    ),
                    "p7b_sync_wall_fraction_gate_pass": r.get(
                        "p7b_sync_wall_fraction_gate_pass"
                    ),
                    "p7b_sync_wall_absolute_gate_pass": r.get(
                        "p7b_sync_wall_absolute_gate_pass"
                    ),
                    "p7b_h2d_gate_pass": r.get("p7b_h2d_gate_pass"),
                    "response_communication_envelope_bytes": r.get(
                        "response_communication_envelope_bytes"
                    ),
                    "response_communication_observed_bytes": r.get(
                        "response_communication_observed_bytes"
                    ),
                    "response_communication_invariant_pass": r.get(
                        "response_communication_invariant_pass"
                    ),
                    "p7b_transcript_reference_bytes": r.get(
                        "p7b_transcript_reference_bytes"
                    ),
                    "p7b_pcs_opening_reference_bytes": r.get(
                        "p7b_pcs_opening_reference_bytes"
                    ),
                    "p7b_packed_logits_reference_bytes": r.get(
                        "p7b_packed_logits_reference_bytes"
                    ),
                    "p7b_packed_response_reference_bytes": r.get(
                        "p7b_packed_response_reference_bytes"
                    ),
                    "p7b_response_communication_no_growth_pass": r.get(
                        "p7b_response_communication_no_growth_pass"
                    ),
                    "p7b_all_gates_pass": r.get("p7b_all_gates_pass"),
                    "pcs_n_queries": r.get("pcs_n_queries"),
                    "repetitions": r.get("repetitions"),
                    "pcg_production_ready": r.get("pcg_production_ready"),
                }
            )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_hybrid_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-hybrid", "P7-integrated-hybrid-quick"},
        "cuda-hybrid",
    )


def integrated_resident_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-resident", "P7-integrated-resident-quick"},
        "cuda-resident",
    )


def integrated_p7b_resident_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7b-integrated-resident", "P7b-integrated-resident-quick"},
        "cuda-resident",
        include_p7b_fields=True,
    )


def resident_run_of_record_eligible(row: dict[str, Any]) -> bool:
    """Require schema-4 arena invariants while retaining historical schema-3 records."""
    if row.get("milestone") != "P7-integrated-resident" or row.get("git_dirty", True):
        return False
    schema = row.get("report_schema_version") or 0
    # P7 is a closed historical artifact. Later P7b schemas must never replace
    # its negative run of record even if a caller mislabels one as P7.
    if schema > 4 or row.get("p7b_gate_evaluated") is not None:
        return False
    if schema < 4:
        return True
    return (
        row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )


def p7b_resident_run_of_record_eligible(row: dict[str, Any]) -> bool:
    """Recognize a complete official P7b verdict, whether performance passes or fails.

    This is intentionally a fail-closed schema validator, not a selector for
    successful runs. A valid measured failure is a run of record; missing or
    internally inconsistent gate evidence is not.
    """
    fixed_invariants = (
        row.get("milestone") == "P7b-integrated-resident"
        and type(row.get("report_schema_version")) is int
        and row.get("report_schema_version") == P7B_REPORT_SCHEMA_VERSION
        and row.get("accelerator_backend") == "cuda-resident"
        and type(row.get("accelerator_cuda_abi_version")) is int
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == P7B_GATE_PROFILE
        and row.get("accepted") is True
        and row.get("git_dirty") is False
        and row.get("git_dirty_before_benchmark") is False
        and row.get("git_dirty_before_serialization") is False
        and _p7b_git_provenance_valid(row)
        and _p7b_machine_metadata_valid(row)
        and row.get("p7b_machine_eligible") is True
        and row.get("p7b_gate_evaluated") is True
        and type(row.get("benchmark_warmup_repetitions")) is int
        and row.get("benchmark_warmup_repetitions") >= 1
        and type(row.get("benchmark_repetitions")) is int
        and row.get("benchmark_repetitions") >= 3
        and type(row.get("t_prefill")) is int
        and row.get("t_prefill") == 100
        and type(row.get("n_decode")) is int
        and row.get("n_decode") == 50
        and type(row.get("pcs_n_queries")) is int
        and row.get("pcs_n_queries") == 200
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("flat_cost_gate") is True
        and _finite_nonnegative(row.get("flat_cost_last_over_first"))
        and row.get("flat_cost_last_over_first") <= 1.5
        and row.get("pcg_backend") == "mock"
        and row.get("pcg_production_ready") is False
        and row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )
    repetitions = row.get("repetitions")
    timing_policy_valid = isinstance(repetitions, list) and all(
        isinstance(repetition, dict)
        and isinstance(repetition.get("accelerator_session"), dict)
        and repetition["accelerator_session"].get("timing_method")
        == P7B_OFFICIAL_SESSION_TIMING_METHOD
        and repetition["accelerator_session"].get("phase_attribution_available") is False
        and type(repetition["accelerator_session"].get("timing_records")) is int
        and repetition["accelerator_session"]["timing_records"] == 0
        and type(repetition["accelerator_session"].get("timing_elapsed_query_attempts"))
        is int
        and repetition["accelerator_session"]["timing_elapsed_query_attempts"] == 0
        and type(repetition["accelerator_session"].get("timing_elapsed_no_write")) is int
        and repetition["accelerator_session"]["timing_elapsed_no_write"] == 0
        and type(repetition["accelerator_session"].get("timing_event_queries")) is int
        and repetition["accelerator_session"]["timing_event_queries"] == 0
        and type(repetition["accelerator_session"].get("timing_event_api_calls")) is int
        and repetition["accelerator_session"]["timing_event_api_calls"] == 0
        and _nonnegative_int(
            repetition["accelerator_session"].get("resident_h2d_host_calls")
        )
        and _nonnegative_int(
            repetition["accelerator_session"].get("resident_d2h_host_calls")
        )
        and _finite_nonnegative(
            repetition["accelerator_session"].get("resident_h2d_host_call_s")
        )
        and _finite_nonnegative(
            repetition["accelerator_session"].get("resident_d2h_host_call_s")
        )
        for repetition in repetitions
    )
    return (
        fixed_invariants
        and timing_policy_valid
        and _p7b_sampling_statistics_valid(row)
        and _p7b_communication_valid(row)
        and _p7b_performance_verdict_valid(row)
    )


def validate_p7b_official_result(path: Path) -> bool:
    """Validate one raw JSON through the same projection and fail-closed selector."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict):
        return False
    raw["_path"] = str(path)
    try:
        raw["_mtime"] = path.stat().st_mtime
    except OSError:
        return False
    rows = integrated_p7b_resident_profiles([raw])
    return len(rows) == 1 and p7b_resident_run_of_record_eligible(rows[0])


def validate_fase_d_pod_official_result(path: Path) -> bool:
    """Fail closed on the preregistered fase-D G4 raw artifact."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict):
        return False
    raw["_path"] = str(path)
    try:
        raw["_mtime"] = path.stat().st_mtime
    except OSError:
        return False
    rows = integrated_accelerator_profiles(
        [raw], {"fase-D-G4"}, "cuda-resident", include_p7b_fields=True
    )
    if len(rows) != 1:
        return False
    row = rows[0]
    cloud = raw.get("cloud")
    cloud_fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    setup = raw.get("fase_d_setup")
    lifecycle = raw.get("fase_d_lifecycle")
    setup_comm = setup.get("comm") if isinstance(setup, dict) else None
    capacity = setup.get("capacity") if isinstance(setup, dict) else None
    pcs_rows = raw.get("pcs_commitments")
    repetitions = raw.get("repetitions")
    timing_policy_valid = isinstance(repetitions, list) and all(
        isinstance(repetition, dict)
        and isinstance(repetition.get("accelerator_session"), dict)
        and repetition["accelerator_session"].get("timing_method")
        == P7B_OFFICIAL_SESSION_TIMING_METHOD
        and repetition["accelerator_session"].get("phase_attribution_available") is False
        and repetition["accelerator_session"].get("timing_records") == 0
        and repetition["accelerator_session"].get("timing_elapsed_query_attempts") == 0
        and repetition["accelerator_session"].get("timing_elapsed_no_write") == 0
        and repetition["accelerator_session"].get("timing_event_queries") == 0
        and repetition["accelerator_session"].get("timing_event_api_calls") == 0
        for repetition in repetitions
    )
    fixed = (
        raw.get("report_schema_version") == FASE_D_POD_REPORT_SCHEMA_VERSION
        and raw.get("milestone") == "fase-D-G4"
        and raw.get("accelerator_backend") == "cuda-resident"
        and raw.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and raw.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and raw.get("p7b_gate_profile")
        in (FASE_D_POD_GATE_PROFILE_V1, FASE_D_POD_GATE_PROFILE_V2)
        and raw.get("accepted") is True
        and raw.get("chunked_accepted") is True
        and raw.get("git_dirty") is False
        and raw.get("git_dirty_before_benchmark") is False
        and raw.get("git_dirty_before_serialization") is False
        and _p7b_git_provenance_valid(raw)
        and isinstance(cloud, dict)
        and all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in cloud_fields)
        and cloud.get("provider") == "RunPod"
        and cloud.get("gpu_sku") == "NVIDIA A100-SXM4-80GB"
        and raw.get("threads") == P7B_OFFICIAL_RAYON_THREADS
        and raw.get("p7b_machine_eligible") is True
        and raw.get("p7b_gate_evaluated") is True
        and raw.get("benchmark_warmup_repetitions", 0) >= 1
        and raw.get("benchmark_repetitions", 0) >= 3
        and raw.get("t_prefill") == 100
        and raw.get("n_decode") == 50
        and raw.get("pcs_n_queries") == 200
        and raw.get("golden_decode_checked") is True
        and raw.get("golden_decode_match") is True
        and raw.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(raw.get("curve_last_over_first"))
        and raw.get("curve_last_over_first") <= 1.5
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 13
        and all(isinstance(pcs, dict) and pcs.get("verified") is True for pcs in pcs_rows)
        and raw.get("n_weight_claims") == 96
        and raw.get("n_embed_claims") == 6
        and raw.get("pcg_backend") == "real"
        and raw.get("ggm_prg") == "aes128-mmo"
        and raw.get("pcg_production_ready") is True
        and raw.get("fase_d_g1_pass") is True
        and raw.get("pcg_mock_prepass_counters_match") is True
        and raw.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and raw.get("pcg_mock_prepass_allocation_digest_match") is True
        and raw.get("pcg_allocation_hash_match") is True
        and raw.get("comm_response_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and raw.get("pcs_opening_bytes_total") == C1_PCS_OPENING_REFERENCE_BYTES
        and raw.get("public_logits_packed_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and raw.get("total_response_download_packed_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("response_communication_observed_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("p7b_transcript_reference_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and raw.get("p7b_pcs_opening_reference_bytes") == C1_PCS_OPENING_REFERENCE_BYTES
        and raw.get("p7b_packed_logits_reference_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and raw.get("p7b_packed_response_reference_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("response_communication_invariant_pass") is True
        and raw.get("p7b_response_communication_no_growth_pass") is True
        and isinstance(setup, dict)
        and setup.get("ggm_prg") == "aes128-mmo"
        and setup.get("pcg_production_ready") is True
        and setup.get("one_connection_base_phase") is True
        and setup.get("g2_capacity_gate_pass") is True
        and setup.get("g2_traffic_gate_pass") is True
        and isinstance(setup_comm, dict)
        and _nonnegative_int(setup_comm.get("total_bytes"))
        and setup_comm["total_bytes"] <= 40_000_000
        and isinstance(capacity, dict)
        and capacity.get("allocatable_stage3", 0) >= 110_000_000
        and isinstance(lifecycle, dict)
        and lifecycle.get("completed_responses", 0) >= 5
        and lifecycle.get("responses_after_first_repeat_base_ot_bytes") == 0
        and lifecycle.get("responses_after_first_repeat_ot_extension_bytes") == 0
        and row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )
    return (
        fixed
        and timing_policy_valid
        and _p7b_sampling_statistics_valid(row)
        and _p7b_performance_verdict_valid(row)
    )


def _c3b_timing_distribution_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    samples = value.get("samples_s")
    return isinstance(samples, list) and _timing_distribution_valid(value, samples)


def _c3b_g2_valid(value: Any, *, pod: bool) -> bool:
    if not isinstance(value, dict):
        return False
    baseline = value.get("baseline_prove_response")
    candidate = value.get("candidate_prove_response")
    if not (
        _c3b_timing_distribution_valid(baseline)
        and _c3b_timing_distribution_valid(candidate)
        and _finite_positive(value.get("baseline_s"))
        and _finite_nonnegative(value.get("candidate_s"))
        and _finite_number(value.get("delta_s"))
        and _finite_number(value.get("delta_percent"))
        and value.get("gate_percent") == 15.0
        and _finite_positive(value.get("ceiling_s"))
        and type(value.get("pass")) is bool
        and _same_number(value["baseline_s"], baseline["median_s"])
        and _same_number(value["candidate_s"], candidate["median_s"])
        and _same_finite_number(value["delta_s"], value["candidate_s"] - value["baseline_s"])
        and _same_finite_number(
            value["delta_percent"], value["delta_s"] / value["baseline_s"] * 100.0
        )
        and value["pass"] is (value["candidate_s"] <= value["ceiling_s"])
    ):
        return False
    if pod:
        return (
            value.get("timing_policy")
            == "wall-only+counters; upper median candidate; pinned same-host control"
            and value.get("baseline_source")
            == (
                "c3b-l4-ablation-diagnostic-2026-07-18-5a2edbe.json; "
                "pinned rounded median"
            )
            and value["baseline_s"] == C3B_G2_POD_BASELINE_S
            and value["ceiling_s"] == C3B_G2_POD_CEILING_S
        )
    return (
        value.get("timing_policy")
        == "same-process ABBA; one paired warmup + three rounds; protocol-core prove wall"
        and value.get("baseline_source")
        == "unchanged fase-D Q=200 public-logit response arm in this record"
        and len(baseline["samples_s"]) == 6
        and len(candidate["samples_s"]) == 6
        and _same_number(value["ceiling_s"], value["baseline_s"] * 1.15)
    )


def _c3b_spool_and_lifecycle_valid(row: dict[str, Any]) -> bool:
    setup = row.get("fase_d_setup")
    lifecycle = row.get("fase_d_lifecycle")
    if not isinstance(setup, dict) or not isinstance(lifecycle, dict):
        return False
    entries = setup.get("correlation_spool_entries")
    spool_bytes = setup.get("correlation_spool_bytes")
    setup_comm = setup.get("comm")
    return (
        setup.get("ggm_prg") == "aes128-mmo"
        and setup.get("pcg_production_ready") is True
        and setup.get("one_connection_base_phase") is True
        and setup.get("g2_capacity_gate_pass") is True
        and setup.get("g2_traffic_gate_pass") is True
        and setup.get("correlation_storage")
        == "unlinked-0600-file; connection-scoped; range-read only; page-cache discarded"
        and _nonnegative_int(entries)
        and entries >= 110_000_000
        and _nonnegative_int(spool_bytes)
        and spool_bytes == entries * 40
        and setup.get("correlation_spool_chunk_entries") == 1 << 16
        and setup.get("correlation_spool_resident_raw_entries") == 0
        and _finite_nonnegative(setup.get("correlation_spool_write_wall_s"))
        and _full_hex_digest(setup.get("correlation_spool_digest"))
        and isinstance(setup_comm, dict)
        and _nonnegative_int(setup_comm.get("total_bytes"))
        and setup_comm["total_bytes"] <= 40_000_000
        and row.get("pcg_setup_comm_bytes") == setup_comm["total_bytes"]
        and lifecycle.get("completed_responses", 0) >= 4
        and lifecycle.get("responses_after_first_repeat_base_ot_bytes") == 0
        and lifecycle.get("responses_after_first_repeat_ot_extension_bytes") == 0
        and isinstance(lifecycle.get("response_base_ot_bytes"), list)
        and len(lifecycle["response_base_ot_bytes"]) == lifecycle["completed_responses"]
        and isinstance(lifecycle.get("response_ot_extension_bytes"), list)
        and len(lifecycle["response_ot_extension_bytes"]) == lifecycle["completed_responses"]
    )


def _c3b_common_record_valid(row: dict[str, Any]) -> bool:
    transcript_labels = row.get("comm_response_by_label")
    pcs_labels = row.get("comm_pcs_by_label")
    pcs_rows = row.get("pcs_commitments")
    common = (
        row.get("report_schema_version") == C3B_REPORT_SCHEMA_VERSION
        and row.get("milestone") == "C3b"
        and row.get("git_dirty") is False
        and _full_git_sha(row.get("git_sha"))
        and row.get("benchmark_warmup_repetitions", 0) >= 1
        and row.get("benchmark_repetitions", 0) >= 3
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("chunked_accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(row.get("curve_last_over_first"))
        and row["curve_last_over_first"] <= 1.5
        and row.get("c3_packed_response_gate_bytes") == C3B_PACKED_RESPONSE_GATE_BYTES
        and row.get("comm_response_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("pcs_opening_bytes_total") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("public_logits_bytes") == 0
        and row.get("public_logits_packed_bytes") == 0
        and row.get("total_response_download_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(transcript_labels, dict)
        and all(_nonnegative_int(value) for value in transcript_labels.values())
        and sum(transcript_labels.values()) == C3B_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(pcs_labels, dict)
        and all(_nonnegative_int(value) for value in pcs_labels.values())
        and sum(pcs_labels.values()) == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 120
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 2
        and all(isinstance(item, dict) and item.get("verified") is True for item in pcs_rows)
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("c3b_l4_transcript_bytes") == C3B_L4_TRANSCRIPT_BYTES
        and row.get("c3b_transcript_reference_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("c3b_limb_count") == C3B_LIMBS
        and row.get("c3b_range_instances") == C3B_RANGE_INSTANCES
        and row.get("c3b_real_comparisons") == C3B_REAL_COMPARISONS
        and row.get("c3b_packed_entries_per_limb") == C3B_PACKED_ENTRIES_PER_LIMB
        and row.get("c3b_packed_entries_total") == C3B_PACKED_ENTRIES_TOTAL
        and _same_number(
            row.get("c3b_padding_ratio"),
            C3B_PACKED_ENTRIES_PER_LIMB / C3B_REAL_COMPARISONS,
        )
        and row.get("c3b_l4_emult_instances") == C3B_L4_EMULT_INSTANCES
        and row.get("c3b_l4_emult_ceiling") == C3B_L4_EMULT_CEILING
        and row.get("c3b_l4_emult_gate_pass") is True
        and row.get("emult_instances_total") == C3B_EMULT_INSTANCES_TOTAL
        and row.get("c3b_exact_instance_counter_pass") is True
        and row.get("c3b_transcript_category_sum_pass") is True
        and row.get("c3b_pcs_category_sum_pass") is True
        and row.get("c3b_public_logits_disabled") is True
        and row.get("pcg_backend") == "real"
        and row.get("ggm_prg") == "aes128-mmo"
        and row.get("pcg_production_ready") is True
        and row.get("pcg_setup_instances") == 1
        and row.get("pcg_setup_wire_count_invariant_pass") is True
        and row.get("pcg_mock_prepass_counters_match") is True
        and row.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and row.get("pcg_mock_prepass_allocation_digest_match") is True
        and row.get("pcg_allocation_hash_match") is True
        and row.get("pcg_response_authorization_burned_before_setup") is True
        and row.get("pcg_burn_on_success_or_abort") is True
        and row.get("pcg_reconnect_retry_resume_allowed") is False
    )
    return common and _c3b_spool_and_lifecycle_valid(row)


def _c3b_resident_cleanup_valid(row: dict[str, Any]) -> bool:
    cleanup = (
        row.get("accelerator_live_device_bytes_after_cleanup"),
        row.get("accelerator_workspace_device_bytes_after_cleanup"),
        row.get("accelerator_resident_device_bytes_after_cleanup"),
        row.get("accelerator_cached_resident_device_bytes_after_cleanup"),
    )
    trimmed = (
        row.get("accelerator_live_device_bytes_after_cache_trim"),
        row.get("accelerator_workspace_device_bytes_after_cache_trim"),
        row.get("accelerator_resident_device_bytes_after_cache_trim"),
        row.get("accelerator_cached_resident_device_bytes_after_cache_trim"),
    )
    return (
        all(_nonnegative_int(value) for value in cleanup + trimmed)
        and cleanup[0] == cleanup[1] + cleanup[2] + cleanup[3]
        and trimmed[0] == trimmed[1] + trimmed[2] + trimmed[3]
        and cleanup[2] == 0
        and trimmed[2] == 0
        and trimmed[3] == 0
    )


def _realpcg_pod_metadata_valid(row: dict[str, Any]) -> bool:
    cloud = row.get("cloud")
    fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    return (
        isinstance(cloud, dict)
        and all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in fields)
        and cloud.get("provider") == "RunPod"
        and cloud.get("gpu_sku") == "NVIDIA A100-SXM4-80GB"
        and row.get("threads") == P7B_OFFICIAL_RAYON_THREADS
    )


def _c3b_pod_record_valid(row: dict[str, Any]) -> bool:
    g2 = row.get("c3b_g2")
    communication = (
        row.get("response_communication_envelope_bytes") == 200_000_000
        and row.get("response_communication_observed_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_transcript_reference_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == 0
        and row.get("p7b_packed_response_reference_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_response_communication_no_growth_pass") is True
    )
    fixed = (
        row.get("accelerator_backend") == "cuda-resident"
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == C3B_POD_GATE_PROFILE
        and row.get("p7b_gate_evaluated") is True
        and row.get("p7b_machine_eligible") is True
        and _p7b_git_provenance_valid(row)
        and _realpcg_pod_metadata_valid(row)
        and _c3b_g2_valid(g2, pod=True)
        and communication
        and _c3b_resident_cleanup_valid(row)
    )
    if not fixed:
        return False
    performance = _p7b_sampling_statistics_valid(row) and _p7b_performance_verdict_valid(row)
    expected_g4 = performance and row.get("p7b_all_gates_pass") is True and g2["pass"]
    return performance and row.get("c3b_g4_pass") is expected_g4


def _c3b_cpu_record_valid(row: dict[str, Any]) -> bool:
    return (
        row.get("accelerator_backend") == "cpu"
        and row.get("threads") == 4
        and row.get("c3b_g1_pass") is True
        and row.get("c3b_g4_pass") is None
        and _c3b_g2_valid(row.get("c3b_g2"), pod=False)
    )


def validate_c3b_official_result(path: Path) -> bool:
    """Fail closed on either half of the paired schema-9 C3b verdict."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or not _c3b_common_record_valid(raw):
        return False
    if raw.get("accelerator_backend") == "cpu":
        return _c3b_cpu_record_valid(raw)
    if raw.get("accelerator_backend") == "cuda-resident":
        return _c3b_pod_record_valid(raw)
    return False


def _t1_g2_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    baseline = value.get("baseline_prove_response")
    candidate = value.get("candidate_prove_response")
    if not (
        _c3b_timing_distribution_valid(baseline)
        and _c3b_timing_distribution_valid(candidate)
        and len(baseline["samples_s"]) == 6
        and len(candidate["samples_s"]) == 6
        and _finite_positive(value.get("baseline_s"))
        and _finite_nonnegative(value.get("candidate_s"))
        and _finite_number(value.get("delta_s"))
        and _finite_number(value.get("delta_percent"))
        and value.get("gate_percent") == 5.0
        and _finite_positive(value.get("ceiling_s"))
        and type(value.get("pass")) is bool
        and value.get("timing_policy")
        == "same-process ABBA; one paired warmup + three rounds; protocol-core prove wall"
        and value.get("baseline_source")
        == "frozen C3b boundary-authentication control arm in this binary"
        and _same_number(value["baseline_s"], baseline["median_s"])
        and _same_number(value["candidate_s"], candidate["median_s"])
        and _same_finite_number(value["delta_s"], value["candidate_s"] - value["baseline_s"])
        and _same_finite_number(
            value["delta_percent"], value["delta_s"] / value["baseline_s"] * 100.0
        )
        and _same_number(value["ceiling_s"], value["baseline_s"] * 1.05)
    ):
        return False
    return value["pass"] is (value["candidate_s"] <= value["ceiling_s"])


def _t1_common_record_valid(row: dict[str, Any]) -> bool:
    transcript_labels = row.get("comm_response_by_label")
    pcs_labels = row.get("comm_pcs_by_label")
    pcs_rows = row.get("pcs_commitments")
    reducer_bytes = None
    if isinstance(transcript_labels, dict):
        reducer_bytes = transcript_labels.get("t1_eq_round_corrections", 0) + transcript_labels.get(
            "t1_eq_terminal_correction", 0
        )
    common = (
        row.get("report_schema_version") == T1_REPORT_SCHEMA_VERSION
        and row.get("milestone") in ("T1-G1", "T1-G4")
        and row.get("git_dirty") is False
        and _full_git_sha(row.get("git_sha"))
        and row.get("benchmark_warmup_repetitions", 0) >= 1
        and row.get("benchmark_repetitions", 0) >= 3
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("chunked_accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(row.get("curve_last_over_first"))
        and row["curve_last_over_first"] <= 1.5
        and row.get("t1_response_gate_bytes") == T1_RESPONSE_GATE_BYTES
        and row.get("t1_response_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("comm_response_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("total_response_download_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("t1_auth_correction_gate_bytes") == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and row.get("t1_auth_correction_reference_bytes")
        == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and isinstance(transcript_labels, dict)
        and all(_nonnegative_int(value) for value in transcript_labels.values())
        and sum(transcript_labels.values()) == T1_RESPONSE_REFERENCE_BYTES
        and transcript_labels.get("auth_corrections") == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and reducer_bytes == T1_EQ_REDUCER_TRANSCRIPT_BYTES
        and transcript_labels.get("t1_q_bridge_correction")
        == T1_Q_BRIDGE_CORRECTION_BYTES
        and row.get("t1_eq_reducer_transcript_bytes") == T1_EQ_REDUCER_TRANSCRIPT_BYTES
        and row.get("t1_q_bridge_correction_bytes") == T1_Q_BRIDGE_CORRECTION_BYTES
        and row.get("pcs_opening_bytes_total") == C3B_PCS_OPENING_REFERENCE_BYTES
        and isinstance(pcs_labels, dict)
        and all(_nonnegative_int(value) for value in pcs_labels.values())
        and sum(pcs_labels.values()) == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 120
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 2
        and all(isinstance(item, dict) and item.get("verified") is True for item in pcs_rows)
        and row.get("public_logits_bytes") == 0
        and row.get("public_logits_packed_bytes") == 0
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("closure_prod_claims") == T1_PROD_CLAIMS
        and row.get("closure_zero_claims") == T1_ZERO_CLAIMS
        and row.get("corr_sub_corrs") == T1_SUB_CORRS
        and row.get("corr_full_corrs") == T1_FULL_CORRS
        and row.get("emult_instances_total") == T1_EMULT_INSTANCES_TOTAL
        and row.get("t1_emult_other_total") == T1_EMULT_OTHER_TOTAL
        and row.get("t1_exact_counter_pass") is True
        and row.get("t1_g3_pass") is True
        and row.get("c3b_transcript_category_sum_pass") is True
        and row.get("c3b_pcs_category_sum_pass") is True
        and row.get("c3b_public_logits_disabled") is True
        and row.get("pcg_backend") == "real"
        and row.get("ggm_prg") == "aes128-mmo"
        and row.get("pcg_production_ready") is True
        and row.get("pcg_setup_instances") == 1
        and row.get("pcg_setup_wire_count_invariant_pass") is True
        and row.get("pcg_mock_prepass_counters_match") is True
        and row.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and row.get("pcg_mock_prepass_allocation_digest_match") is True
        and row.get("pcg_allocation_hash_match") is True
        and row.get("pcg_response_authorization_burned_before_setup") is True
        and row.get("pcg_burn_on_success_or_abort") is True
        and row.get("pcg_reconnect_retry_resume_allowed") is False
    )
    return common and _c3b_spool_and_lifecycle_valid(row)


def _t1_cpu_record_valid(row: dict[str, Any]) -> bool:
    g2 = row.get("t1_g2")
    return (
        row.get("milestone") == "T1-G1"
        and row.get("accelerator_backend") == "cpu"
        and row.get("threads") == 4
        and _t1_g2_valid(g2)
        and row.get("t1_g1_pass") is g2["pass"]
        and row.get("t1_g4_pass") is None
    )


def _t1_pod_record_valid(row: dict[str, Any]) -> bool:
    communication = (
        row.get("response_communication_envelope_bytes") == 200_000_000
        and row.get("response_communication_observed_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_transcript_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == 0
        and row.get("p7b_packed_response_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("p7b_response_communication_no_growth_pass") is True
    )
    fixed = (
        row.get("milestone") == "T1-G4"
        and row.get("accelerator_backend") == "cuda-resident"
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == T1_POD_GATE_PROFILE
        and row.get("p7b_gate_evaluated") is True
        and row.get("p7b_machine_eligible") is True
        and _p7b_git_provenance_valid(row)
        and _realpcg_pod_metadata_valid(row)
        and row.get("t1_g1_pass") is None
        and row.get("t1_g2") is None
        and communication
        and _c3b_resident_cleanup_valid(row)
    )
    if not fixed:
        return False
    performance = _p7b_sampling_statistics_valid(row) and _p7b_performance_verdict_valid(row)
    expected_g4 = performance and row.get("p7b_all_gates_pass") is True
    return performance and row.get("t1_g4_pass") is expected_g4


def validate_t1_official_result(path: Path) -> bool:
    """Fail closed on either half of the paired schema-10 T1 verdict."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or not _t1_common_record_valid(raw):
        return False
    if raw.get("accelerator_backend") == "cpu":
        return _t1_cpu_record_valid(raw)
    if raw.get("accelerator_backend") == "cuda-resident":
        return _t1_pod_record_valid(raw)
    return False


def _finite_nonnegative(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _finite_positive(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _finite_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _same_number(left: Any, right: Any) -> bool:
    return _finite_nonnegative(left) and _finite_nonnegative(right) and math.isclose(
        left, right, rel_tol=0.0, abs_tol=1e-12
    )


def _same_finite_number(left: Any, right: Any) -> bool:
    return _finite_number(left) and _finite_number(right) and math.isclose(
        left, right, rel_tol=0.0, abs_tol=1e-12
    )


def _full_git_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _full_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _p7b_git_provenance_valid(row: dict[str, Any]) -> bool:
    before = row.get("git_sha_before_benchmark")
    after = row.get("git_sha_before_serialization")
    return _full_git_sha(before) and before == after and row.get("git_sha") == before


def _p7b_machine_metadata_valid(row: dict[str, Any]) -> bool:
    cloud = row.get("cloud")
    if not isinstance(cloud, dict):
        return False
    fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    if not all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in fields):
        return False
    expected = {
        "provider": "RunPod",
        "region": "eur-is-1",
        "image": "Ubuntu 24.04.3 LTS",
        "driver_version": "580.159.04",
        "cuda_version": "12.8",
        "gpu_sku": "NVIDIA A100-SXM4-80GB",
        "cpu_model": "AMD EPYC 7713 64-Core Processor",
        "ram_gib": "1008",
        "vcpus": "255",
    }
    return (
        type(row.get("threads")) is int
        and row["threads"] == P7B_OFFICIAL_RAYON_THREADS
        and all(cloud.get(field) == value for field, value in expected.items())
    )


def _timing_distribution_valid(timing: Any, samples: list[float]) -> bool:
    if not isinstance(timing, dict) or timing.get("samples_s") != samples or not samples:
        return False
    if not all(_finite_nonnegative(sample) for sample in samples):
        return False
    upper_median = sorted(samples)[len(samples) // 2]
    return _same_number(timing.get("median_s"), upper_median)


def _p7b_sampling_statistics_valid(row: dict[str, Any]) -> bool:
    measured = row.get("benchmark_repetitions")
    repetitions = row.get("repetitions")
    if (
        type(measured) is not int
        or measured < 3
        or not isinstance(repetitions, list)
        or len(repetitions) != measured
        or row.get("p7b_timing_statistic") != P7B_TIMING_STATISTIC
        or row.get("p7b_counter_statistic") != P7B_COUNTER_STATISTIC
    ):
        return False
    if any(not isinstance(rep, dict) for rep in repetitions):
        return False
    if [rep.get("repetition") for rep in repetitions] != list(range(1, measured + 1)):
        return False
    prefill_samples = [rep.get("t_prove_prefill_only_s") for rep in repetitions]
    decode_samples = [rep.get("t_prove_decode_marginal_s") for rep in repetitions]
    if not _timing_distribution_valid(row.get("prove_prefill_timing"), prefill_samples):
        return False
    if not _timing_distribution_valid(row.get("prove_decode_marginal_timing"), decode_samples):
        return False
    sessions = [rep.get("accelerator_session") for rep in repetitions]
    if any(not isinstance(session, dict) for session in sessions):
        return False
    syncs = [session.get("synchronizations") for session in sessions]
    sync_wall_s = [session.get("synchronization_s") for session in sessions]
    session_wall_s = [rep.get("t_response_session_wall_s") for rep in repetitions]
    sync_wall_fractions = [rep.get("p7b_sync_wall_fraction") for rep in repetitions]
    reported_sync_wall_s = [rep.get("p7b_sync_wall_s") for rep in repetitions]
    h2d = [session.get("h2d_bytes") for session in sessions]
    if (
        not all(_nonnegative_int(value) for value in syncs + h2d)
        or not all(_finite_nonnegative(value) for value in sync_wall_s)
        or not all(_finite_nonnegative(value) and value > 0 for value in session_wall_s)
        or not all(_finite_nonnegative(value) for value in sync_wall_fractions)
    ):
        return False
    expected_sync_wall_fractions = [
        sync_wall / session_wall
        for sync_wall, session_wall in zip(sync_wall_s, session_wall_s, strict=True)
    ]
    if not all(
        _same_number(observed, expected)
        for observed, expected in zip(
            sync_wall_fractions, expected_sync_wall_fractions, strict=True
        )
    ):
        return False
    if any(value is not None for value in reported_sync_wall_s) and not all(
        _same_number(observed, expected)
        for observed, expected in zip(reported_sync_wall_s, sync_wall_s, strict=True)
    ):
        return False
    absolute_observed = row.get("p7b_sync_wall_absolute_observed_s")
    if absolute_observed is not None and not _same_number(absolute_observed, max(sync_wall_s)):
        return False
    return (
        _same_number(
            row.get("p7b_prefill_core_observed_s"),
            row["prove_prefill_timing"]["median_s"],
        )
        and _same_number(
            row.get("p7b_decode_marginal_observed_s"),
            row["prove_decode_marginal_timing"]["median_s"],
        )
        and row.get("p7b_sync_observed") == max(syncs)
        and _same_number(
            row.get("p7b_sync_wall_fraction_observed"),
            max(expected_sync_wall_fractions),
        )
        and row.get("p7b_h2d_observed_bytes") == max(h2d)
    )


def _p7b_communication_valid(row: dict[str, Any]) -> bool:
    communication = row.get("communication")
    if not isinstance(communication, dict):
        return False
    transcript = communication.get("response_bytes")
    pcs = communication.get("pcs_opening_bytes")
    packed_logits = communication.get("public_logits_packed_bytes")
    observed = row.get("response_communication_observed_bytes")
    if not all(_nonnegative_int(value) for value in (transcript, pcs, packed_logits, observed)):
        return False
    return (
        row.get("response_communication_envelope_bytes")
        == P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES
        and row.get("p7b_transcript_reference_bytes") == P7B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == P7B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == P7B_PACKED_LOGITS_REFERENCE_BYTES
        and row.get("p7b_packed_response_reference_bytes")
        == P7B_PACKED_RESPONSE_REFERENCE_BYTES
        and observed == transcript + packed_logits
        and row.get("packed_response_bytes") == observed
        and observed <= P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES
        and transcript <= P7B_TRANSCRIPT_REFERENCE_BYTES
        and pcs <= P7B_PCS_OPENING_REFERENCE_BYTES
        and packed_logits <= P7B_PACKED_LOGITS_REFERENCE_BYTES
        and transcript + packed_logits <= P7B_PACKED_RESPONSE_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_response_communication_no_growth_pass") is True
    )


def _p7b_performance_verdict_valid(row: dict[str, Any]) -> bool:
    absolute_profile = row.get("p7b_gate_profile") in (
        FASE_D_POD_GATE_PROFILE_V2,
        C3B_POD_GATE_PROFILE,
        T1_POD_GATE_PROFILE,
    )
    thresholds = (
        row.get("p7b_prefill_core_gate_s") == P7B_PREFILL_CORE_GATE_S
        and row.get("p7b_decode_marginal_gate_s") == P7B_DECODE_MARGINAL_GATE_S
        and row.get("p7b_sync_count_gate_retired") is True
        and row.get("p7b_h2d_gate_bytes") == P7B_H2D_GATE_BYTES
        and (
            (
                absolute_profile
                and row.get("p7b_sync_wall_fraction_gate") is None
                and row.get("p7b_sync_wall_absolute_gate_s")
                == FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S
            )
            or (
                not absolute_profile
                and row.get("p7b_sync_wall_fraction_gate")
                == P7B_SYNC_WALL_FRACTION_GATE
                and row.get("p7b_sync_wall_absolute_gate_s") is None
            )
        )
    )
    sync_observation = row.get(
        "p7b_sync_wall_absolute_observed_s"
        if absolute_profile
        else "p7b_sync_wall_fraction_observed"
    )
    observations = (
        row.get("p7b_prefill_core_observed_s"),
        row.get("p7b_decode_marginal_observed_s"),
        sync_observation,
        row.get("p7b_h2d_observed_bytes"),
    )
    passes = (
        row.get("p7b_prefill_core_gate_pass"),
        row.get("p7b_decode_marginal_gate_pass"),
        row.get(
            "p7b_sync_wall_absolute_gate_pass"
            if absolute_profile
            else "p7b_sync_wall_fraction_gate_pass"
        ),
        row.get("p7b_h2d_gate_pass"),
    )
    opposite_sync_pass = row.get(
        "p7b_sync_wall_fraction_gate_pass"
        if absolute_profile
        else "p7b_sync_wall_absolute_gate_pass"
    )
    if (
        not thresholds
        or not _finite_nonnegative(observations[0])
        or not _finite_nonnegative(observations[1])
        or not _finite_nonnegative(observations[2])
        or not _nonnegative_int(observations[3])
        or any(type(value) is not bool for value in passes)
        or opposite_sync_pass is not None
        or type(row.get("p7b_all_gates_pass")) is not bool
    ):
        return False
    expected = (
        observations[0] <= P7B_PREFILL_CORE_GATE_S,
        observations[1] <= P7B_DECODE_MARGINAL_GATE_S,
        observations[2]
        <= (
            FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S
            if absolute_profile
            else P7B_SYNC_WALL_FRACTION_GATE
        ),
        observations[3] <= P7B_H2D_GATE_BYTES,
    )
    return passes == expected and row.get("p7b_all_gates_pass") is all(expected)


def shape_memory_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        if result.get("milestone") != "P7-shape-memory-sweep":
            continue
        validation = result.get("validation") or {}
        if not validation or not all(validation.values()):
            continue
        rows.append(
            {
                "_mtime": result["_mtime"],
                "source": result["_path"],
                "git_dirty": result.get("git_dirty"),
                "source_resident_result": result.get("source_resident_result"),
                "source_resident_peak_device_bytes": result.get(
                    "source_resident_peak_device_bytes"
                ),
                "source_resident_workspace_after_cleanup_bytes": result.get(
                    "source_resident_workspace_after_cleanup_bytes"
                ),
                "sequence_lengths": result.get("sequence_lengths"),
                "profiles": result.get("profiles"),
                "validation": validation,
                "scope": result.get("scope"),
            }
        )
    rows.sort(key=lambda row: (row["_mtime"], row["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def same_host_native(
    native_profiles: list[dict[str, Any]], integrated: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not integrated:
        return None
    instance_id = (integrated.get("cloud") or {}).get("instance_id")
    if not instance_id:
        return None
    matches = [
        row
        for row in native_profiles
        if row.get("milestone") == "P7-gpu-native-inference"
        and not row.get("git_dirty", True)
        and (row.get("cloud") or {}).get("instance_id") == instance_id
    ]
    return matches[-1] if matches else None


def integrated_same_host_result(
    proof: dict[str, Any] | None, native: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not proof or not native:
        return None
    proof_rho = {
        "prefill": proof["prove_prefill_s"] / native["prefill_s"],
        "decode": proof["prove_decode_marginal_s"] / native["decode_50_s"],
    }
    result: dict[str, Any] = {
        "same_instance": True,
        "native_source": native["source"],
        "proof_source": proof["source"],
        "rho_definition": "protocol-core prover wall / same-host exact native-GPU inference wall",
        "proof_rho": proof_rho,
        "targets": P7_RHO_TARGETS,
        "target_met": {
            phase: proof_rho[phase] <= P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "required_speedup_to_target": {
            phase: proof_rho[phase] / P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "native_anchor_plus_protocol_core_s": {
            "prefill": native["prefill_s"] + proof["prove_prefill_s"],
            "decode_50": native["decode_50_s"] + proof["prove_decode_marginal_s"],
        },
        "pcs": {
            "commit_offline_s": (proof.get("pcs_commit_timing") or {}).get("median_s"),
            "open_online_s": (proof.get("pcs_open_timing") or {}).get("median_s"),
            "verify_s": (proof.get("pcs_verify_timing") or {}).get("median_s"),
        },
        "pcg": {
            "backend": proof.get("pcg_backend"),
            "setup_offline_s": proof.get("pcg_real_phase_a_total_s"),
            "setup_comm_bytes": proof.get("pcg_setup_comm_bytes"),
            "production_grade": False,
        },
        "verifier_accounted_s": proof.get("verifier_accounted_s"),
        "response_session_wall_s": proof.get("response_session_wall_s"),
    }
    online_response = proof.get("prover_online_accounted_response_s")
    online_decode = proof.get("prover_online_accounted_decode_marginal_s")
    if online_response is not None and online_decode is not None:
        result["online_accounted"] = {
            "definition": "protocol core + PCS opening + final closure exchange; closure contains both local roles",
            "response_s": online_response,
            "decode_marginal_s": online_decode,
            "decode_rho": online_decode / native["decode_50_s"],
        }
    witness_prefill = (proof.get("accelerator_witness") or {}).get("measurement_wall_s")
    witness_response = (proof.get("accelerator_response_witness") or {}).get(
        "measurement_wall_s"
    )
    if witness_prefill is not None and witness_response is not None:
        result["measured_resident_pipeline_s"] = {
            "prefill_inference_plus_protocol_core": witness_prefill
            + proof["prove_prefill_s"],
            "response_inference_plus_online_accounted": (
                witness_response + online_response if online_response is not None else None
            ),
            "response_inference_plus_full_session_wall": (
                witness_response + proof["response_session_wall_s"]
                if proof.get("response_session_wall_s") is not None
                else None
            ),
        }
    return result


def decode_marginal_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        labels = r.get("comm_decode_marginal_by_label")
        if not labels:
            continue
        top = sorted(labels.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        rows.append(
            {
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "comm_decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                "comm_decode_bytes_per_token": r.get("comm_decode_bytes_per_token"),
                "label_sum_bytes": sum(labels.values()),
                "top_labels": [{"label": k, "bytes": v} for k, v in top],
            }
        )
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["source"]))
    return rows


def p7_report(results_dir: Path) -> dict[str, Any]:
    results = load_results(results_dir)
    baseline = select_p6_record(results)
    c1_record = select_c1_record(results)
    packed = select_packed_source(results, baseline)

    public_logits_packed = (
        int(packed["public_logits_packed_bytes"])
        if packed and "public_logits_packed_bytes" in packed
        else int(baseline.get("public_logits_packed_bytes", baseline["public_logits_bytes"]))
    )
    current_packed_download = int(baseline["comm_response_bytes"]) + public_logits_packed

    current_formula = pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6)
    current_measured = int(baseline["pcs_opening_bytes_total"])
    formula_matches = current_formula == current_measured
    mock_pcg = mock_pcg_lower_bounds(results)
    real_pcg = real_pcg_phase_a(results)
    real_pcg_b = real_pcg_phase_b(results)
    gpu_rooflines = gpu_roofline_profiles(results)
    full_gpu_rooflines = [r for r in gpu_rooflines if r["milestone"] == "P7-gpu-roofline"]
    gpu_roofline_record = full_gpu_rooflines[-1] if full_gpu_rooflines else None
    gpu_fused = gpu_fused_epilogue_profiles(results)
    full_gpu_fused = [r for r in gpu_fused if r["milestone"] == "P7-gpu-fused-epilogue"]
    gpu_fused_record = full_gpu_fused[-1] if full_gpu_fused else None
    gpu_logup = gpu_logup_tree_profiles(results)
    full_gpu_logup = [r for r in gpu_logup if r["milestone"] == "P7-gpu-logup-tree"]
    gpu_logup_record = full_gpu_logup[-1] if full_gpu_logup else None
    gpu_logup_rounds = gpu_logup_round_profiles(results)
    full_gpu_logup_rounds = [
        r
        for r in gpu_logup_rounds
        if r["milestone"] == "P7-gpu-logup-rounds" and r["gate_speedup_ge_5_48"]
    ]
    gpu_logup_round_record = full_gpu_logup_rounds[-1] if full_gpu_logup_rounds else None
    gpu_logup_blind_rounds = gpu_logup_blind_round_profiles(results)
    full_gpu_logup_blind_rounds = [
        r
        for r in gpu_logup_blind_rounds
        if r["milestone"] == "P7-gpu-logup-blind-rounds"
        and r["gate_speedup_ge_5_48_and_overhead_le_1_05"]
    ]
    gpu_logup_blind_round_record = (
        full_gpu_logup_blind_rounds[-1] if full_gpu_logup_blind_rounds else None
    )
    gpu_pcs = gpu_pcs_arithmetic_profiles(results)
    full_gpu_pcs = [r for r in gpu_pcs if r["milestone"] == "P7-gpu-pcs-arithmetic"]
    gpu_pcs_record = full_gpu_pcs[-1] if full_gpu_pcs else None
    gpu_blake3 = gpu_blake3_merkle_profiles(results)
    full_gpu_blake3 = [r for r in gpu_blake3 if r["milestone"] == "P7-gpu-blake3-merkle"]
    gpu_blake3_record = full_gpu_blake3[-1] if full_gpu_blake3 else None
    gpu_hybrid = integrated_hybrid_profiles(results)
    full_gpu_hybrid = [
        r
        for r in gpu_hybrid
        if r["milestone"] == "P7-integrated-hybrid" and not r.get("git_dirty", True)
    ]
    gpu_hybrid_record = full_gpu_hybrid[-1] if full_gpu_hybrid else None
    gpu_resident = integrated_resident_profiles(results)
    full_gpu_resident = [
        r
        for r in gpu_resident
        if resident_run_of_record_eligible(r)
    ]
    gpu_resident_record = full_gpu_resident[-1] if full_gpu_resident else None
    shape_memory = shape_memory_profiles(results)
    clean_shape_memory = [row for row in shape_memory if not row.get("git_dirty", True)]
    shape_memory_record = clean_shape_memory[-1] if clean_shape_memory else None
    gpu_native = gpu_native_inference_profiles(results)
    full_gpu_native = [
        r
        for r in gpu_native
        if r["milestone"] == "P7-gpu-native-inference" and not r.get("git_dirty", True)
    ]
    resident_native_record = same_host_native(gpu_native, gpu_resident_record)
    hybrid_native_record = same_host_native(gpu_native, gpu_hybrid_record)
    gpu_native_record = (
        resident_native_record
        or hybrid_native_record
        or (full_gpu_native[-1] if full_gpu_native else None)
    )
    gpu_budget = rho_model(baseline)
    required_prover_gpu_speedup = None
    if gpu_native_record:
        proof_only_budget = {
            "prefill_s": gpu_native_record["prefill_s"] * P7_RHO_TARGETS["prefill"],
            "decode_50_s": gpu_native_record["decode_50_s"] * P7_RHO_TARGETS["decode"],
        }
        if (gpu_native_record.get("baseline") or {}).get("source") == baseline["_path"]:
            relative = gpu_budget["required_relative_prover_vs_native_speedup"]
            native = gpu_native_record["native_gpu_speedup"]
            required_prover_gpu_speedup = {
                phase: relative[phase] * native[phase] for phase in ("prefill", "decode")
            }
    else:
        proof_only_budget = None
    integrated_hybrid_rho = integrated_same_host_result(
        gpu_hybrid_record, hybrid_native_record
    )
    integrated_resident_rho = integrated_same_host_result(
        gpu_resident_record, resident_native_record
    )
    if integrated_hybrid_rho:
        # Preserve the schema consumed by the historical hybrid artifact.
        integrated_hybrid_rho["required_speedup_from_hybrid_to_target"] = (
            integrated_hybrid_rho["required_speedup_to_target"]
        )
        integrated_hybrid_rho["inference_plus_proving_s"] = integrated_hybrid_rho[
            "native_anchor_plus_protocol_core_s"
        ]
    pcg_status = (
        "phase_b_measured_not_production"
        if real_pcg_b
        else "phase_a_measured_mock_stub" if real_pcg else "not_measured_in_local_vm"
    )
    pcg_note = (
        "Real-PCG phase B setup measured, but production_ready is false until WYKW malicious checks and table-derived LPN parameters are closed."
        if real_pcg_b
        else (
        "Real-PCG phase A measured with a mock-stub base VOLE; phase B still needs real base OTs/OT extension/setup communication."
        if real_pcg
        else "P7 final go/no-go still needs a real silent-VOLE setup/expansion measurement for this volume."
        )
    )

    p6_comm = {
        "source": baseline["_path"],
        "packed_logits_source": packed["_path"] if packed else None,
        "comm_prefill_bytes": baseline["comm_prefill_bytes"],
        "comm_decode_marginal_bytes": baseline["comm_decode_marginal_bytes"],
        "comm_decode_bytes_per_token": baseline["comm_decode_bytes_per_token"],
        "pcs_opening_bytes": current_measured,
        "public_logits_raw_bytes": baseline["public_logits_bytes"],
        "public_logits_packed_bytes": public_logits_packed,
        "total_response_download_raw_bytes": int(baseline["comm_response_bytes"])
        + int(baseline["public_logits_bytes"]),
        "total_response_download_packed_bytes": current_packed_download,
    }

    report = {
        "report_schema_version": 4 if gpu_resident_record else 2,
        "milestone": "P7",
        "date": _dt.date.today().isoformat(),
        "git_sha": git(["rev-parse", "--short", "HEAD"]),
        "git_dirty": git_dirty(),
        "machine": f"{platform.system().lower()} {platform.machine()}",
        "cloud": (
            gpu_resident_record.get("cloud")
            if gpu_resident_record
            else gpu_hybrid_record.get("cloud")
            if gpu_hybrid_record
            else baseline.get("cloud")
        ),
        "baseline": {
            "source": baseline["_path"],
            "git_dirty": baseline.get("git_dirty"),
            "cloud": baseline.get("cloud"),
            "accepted": baseline.get("accepted"),
            "t_prefill": baseline.get("t_prefill"),
            "n_decode": baseline.get("n_decode"),
            "rho_prefill_cpu": baseline.get("rho_prefill"),
            "rho_decode_cpu": baseline.get("rho_decode"),
            "prove_response_s": baseline.get("t_prove_response_s"),
            "prove_decode_marginal_s": baseline.get("t_prove_decode_marginal_s"),
            "verify_response_s": baseline.get("t_verify_response_s"),
            "pcs_open_s": baseline.get("pcs_open_total_s"),
            "pcs_verify_s": baseline.get("pcs_verify_total_s"),
            "peak_rss_gb": baseline.get("peak_rss_gb"),
        },
        "rho_history": summarize_rhos(results),
        "communication": p6_comm,
        "c1_communication_reference": (
            {
                "source": c1_record["_path"],
                "git_sha": c1_record["git_sha"],
                "response_transcript_bytes": c1_record["comm_response_bytes"],
                "pcs_opening_bytes": c1_record["pcs_opening_bytes_total"],
                "public_logits_packed_bytes": c1_record["public_logits_packed_bytes"],
                "packed_response_bytes": c1_record["total_response_download_packed_bytes"],
                "identity_seam_alias_values": c1_record["c1_identity_seam_reuse"][
                    "identity_seam_alias_values"
                ],
                "historical_runpod_a100_v1_packed_response_bytes": (
                    P7B_PACKED_RESPONSE_REFERENCE_BYTES
                ),
            }
            if c1_record
            else None
        ),
        "measured_pcs_profiles": measured_pcs_profiles(results, baseline),
        "decode_marginal_profiles": decode_marginal_profiles(results),
        "pcs_formula_check": {
            "matches_p6_measured_bytes": formula_matches,
            "formula_total_bytes": current_formula,
            "measured_total_bytes": current_measured,
            "layer_one_opening": multi_open_breakdown(LAYER_PARAMS, 8),
            "embed_opening": multi_open_breakdown(EMBED_PARAMS, 6),
            "rate": rate(LAYER_PARAMS),
            "relative_distance": distance(LAYER_PARAMS),
            "q200_error_bits": query_error_bits(LAYER_PARAMS),
            "q_for_60_bits": queries_for_bits(LAYER_PARAMS, 60.0),
        },
        "pcs_scenarios": pcs_scenarios(baseline, current_packed_download),
        "gpu_budget_model": gpu_budget,
        "gpu_roofline": {
            "status": "measured_screening_pass" if gpu_roofline_record else "not_measured",
            "run_of_record": gpu_roofline_record,
            "profiles": gpu_rooflines,
            "note": "Historical arithmetic screening; full hybrid integration is measured and the device-resident gate remains open.",
        },
        "gpu_fused_epilogue": {
            "status": "measured_gate_pass" if gpu_fused_record else "not_measured",
            "run_of_record": gpu_fused_record,
            "profiles": gpu_fused,
            "note": "Historical P1-equivalent screening; hybrid proving integration landed, resident witness/proving remains open.",
        },
        "gpu_logup_tree": {
            "status": "measured_gate_pass" if gpu_logup_record else "not_measured",
            "run_of_record": gpu_logup_record,
            "profiles": gpu_logup,
            "note": "Historical lookup-tree screening; rounds and hybrid proving integration are now measured separately.",
        },
        "gpu_logup_rounds": {
            "status": "measured_gate_pass" if gpu_logup_round_record else "not_measured",
            "run_of_record": gpu_logup_round_record,
            "profiles": gpu_logup_rounds,
            "note": "Historical clear-round screening; see blind-round and integrated-hybrid sections for correction plumbing and e2e attribution.",
        },
        "gpu_logup_blind_rounds": {
            "status": "measured_gate_pass" if gpu_logup_blind_round_record else "not_measured",
            "run_of_record": gpu_logup_blind_round_record,
            "profiles": gpu_logup_blind_rounds,
            "note": "Historical blind-round screening; aux leaves and corrections are covered by differential/full hybrid integration, resident buffers remain open.",
        },
        "gpu_pcs_arithmetic": {
            "status": "measured_gate_pass" if gpu_pcs_record else "not_measured",
            "run_of_record": gpu_pcs_record,
            "profiles": gpu_pcs,
            "note": "Historical arithmetic screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "gpu_blake3_merkle": {
            "status": "measured_gate_pass" if gpu_blake3_record else "not_measured",
            "run_of_record": gpu_blake3_record,
            "profiles": gpu_blake3,
            "note": "Historical gather/hash screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "integrated_hybrid": {
            "status": (
                "measured_attribution_pass_resident_required"
                if integrated_hybrid_rho
                else "measured_without_same_host_native_anchor"
                if gpu_hybrid_record
                else "not_measured"
            ),
            "run_of_record": gpu_hybrid_record,
            "profiles": gpu_hybrid,
            "same_host_result": integrated_hybrid_rho,
            "note": (
                "Full staged integration preserves correctness, transcript, communication and flat-cost gates, "
                "but H2D/D2H plus CPU residual dominate. This is the attribution gate, not the resident paper result."
            ),
        },
        "integrated_resident": {
            "status": (
                "measured_same_host_targets_pass"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "measured_same_host_targets_fail"
                if integrated_resident_rho
                else "measured_without_same_host_native_anchor"
                if gpu_resident_record
                else "not_measured"
            ),
            "run_of_record": gpu_resident_record,
            "profiles": gpu_resident,
            "same_host_result": integrated_resident_rho,
            "note": (
                "Resident forward, witness and proving share persistent device buffers. "
                "The protocol-core rho remains the preregistered gate; PCS/opening, closures, "
                "verifier, offline commitment and mock-PCG limitations are reported separately "
                "and retained in the measured session wall."
            ),
        },
        "shape_memory_sweep": {
            "status": "analytic_validation_pass" if shape_memory_record else "not_measured",
            "run_of_record": shape_memory_record,
            "profiles": shape_memory,
            "note": (
                "Synthetic formula validation only: GPT-2 is the measured anchor; "
                "Llama-class and gpt-oss rows are not e2e results and project neither "
                "proof time nor proof peak memory."
            ),
        },
        "gpu_native_inference": {
            "status": "measured_exact_golden_pass" if gpu_native_record else "not_measured",
            "run_of_record": gpu_native_record,
            "profiles": gpu_native,
            "required_prover_gpu_speedup_vs_cpu": required_prover_gpu_speedup,
            "proof_only_budget": proof_only_budget,
            "note": "Exact fixed-point full-model prefill and KV decode anchor paired by instance; weights resident, cache-seeding prefill excluded from decode, per-token logits D2H + argmax included.",
        },
        "real_pcg_spike": {
            "status": pcg_status,
            "corr_sub_corrs": baseline.get("corr_sub_corrs"),
            "corr_full_corrs": baseline.get("corr_full_corrs"),
            "mock_pcg_lower_bounds": mock_pcg,
            "real_pcg_phase_a": real_pcg,
            "real_pcg_phase_b": real_pcg_b,
            "note": pcg_note,
        },
        "go_no_go": {
            "local_recommendation": (
                "resident-gates-pass-build-publication-artifact"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "resident-gates-fail-report-result-without-production-claim"
                if integrated_resident_rho
                else "measure-same-host-native-gpu-anchor-for-resident-run"
                if gpu_resident_record
                else "proceed-to-device-resident-prover-integration"
                if integrated_hybrid_rho
                else "measure-same-host-native-gpu-anchor"
                if gpu_hybrid_record
                else "proceed-to-integrated-gpu-prover-measurement"
                if gpu_native_record
                else "proceed-to-proving-path-integration-and-native-gpu-anchor"
                if gpu_logup_blind_round_record
                else "proceed-to-blind-integration-and-native-gpu-anchor"
                if gpu_blake3_record
                else "proceed-to-blake3-merkle-spike"
                if gpu_pcs_record
                else "proceed-to-pcs-hash-spikes"
                if gpu_logup_round_record
                else "proceed-to-logup-rounds-and-pcs-spikes"
                if gpu_logup_record
                else "proceed-to-logup-pcs-kernel-spikes"
                if gpu_fused_record
                else "proceed-to-fused-kernel-spikes"
                if gpu_roofline_record
                else "conditional-go-to-cloud-spikes-only"
            ),
            "summary": (
                "The clean full resident path has a same-host exact native-GPU denominator; "
                "the report retains protocol-core rho, resident inference+proving, full session wall, "
                "PCS/PCG, verifier, communication and memory as separate measured quantities."
                if integrated_resident_rho
                else "Communication, golden decode, verifier and flat-cost gates pass in the full CUDA-hybrid path. "
                "Same-host attribution shows staged transfers and CPU residual dominate by orders of magnitude; "
                "the preregistered resident witness/proving path is required before the final rho go/no-go."
                if integrated_hybrid_rho
                else "Communication is inside the 150-200 MB envelope, but a final rho decision still requires same-host integrated proving and native GPU measurements."
            ),
            "remaining_before_final_go_no_go": (
                []
                if integrated_resident_rho
                else [
                    "device-resident witness consumed directly by the prover without full host materialization",
                    "resident forward/proving share persistent buffers and transfer only protocol messages",
                    "resident 1-warmup/3-repetition full gate passes rho<=10/<=2 with the existing correctness and communication gates",
                ]
                if integrated_hybrid_rho
                else [
                    "same-host native GPU and integrated proving measurements",
                    "device-resident witness/proving path",
                    "golden decode, flat-cost, anti-replay and communication gates",
                ]
            ),
        },
    }
    return report


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem}-{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find unused result path near {path}")


def write_report(report: dict[str, Any], results_dir: Path) -> Path:
    label = f"p7-{report['date']}-{report['git_sha'] or 'unknown'}.json"
    path = unique_path(results_dir / label)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def print_summary(report: dict[str, Any]) -> None:
    comm = report["communication"]
    model = report["gpu_budget_model"]
    print("P7 report")
    print(f"baseline: {report['baseline']['source']} (dirty={report['baseline']['git_dirty']})")
    if comm["packed_logits_source"]:
        print(f"packed logits source: {comm['packed_logits_source']}")
    print()
    print("Communication (MB)")
    print(f"  transcript:          {mb(comm['total_response_download_raw_bytes'] - comm['public_logits_raw_bytes']):8.2f}")
    print(f"  PCS opening:         {mb(comm['pcs_opening_bytes']):8.2f}")
    print(f"  public logits raw:   {mb(comm['public_logits_raw_bytes']):8.2f}")
    print(f"  public logits packed:{mb(comm['public_logits_packed_bytes']):8.2f}")
    print(f"  total raw:           {mb(comm['total_response_download_raw_bytes']):8.2f}")
    print(f"  total packed:        {mb(comm['total_response_download_packed_bytes']):8.2f}")
    print()
    if report.get("measured_pcs_profiles"):
        print("Measured PCS profiles")
        for row in report["measured_pcs_profiles"]:
            packed = row.get("total_response_download_packed_bytes")
            packed_s = f" total={mb(packed):7.2f}" if packed is not None else ""
            print(
                f"  {row['milestone']:<8} Q={row['pcs_n_queries']:<3} "
                f"pcs={mb(row['pcs_opening_bytes_total']):7.2f}{packed_s} "
                f"{row['source']}"
            )
    print()
    pcg = report["real_pcg_spike"].get("mock_pcg_lower_bounds") or []
    if pcg:
        print("Mock-PCG lower bounds")
        for row in pcg:
            print(
                f"  mock total={row['t_total_mock_expansion_s']:.3f}s "
                f"sub={row['corr_sub_corrs']} full={row['corr_full_corrs']} "
                f"{row['source']}"
            )
        print()
    real_pcg = report["real_pcg_spike"].get("real_pcg_phase_a") or []
    if real_pcg:
        print("Real-PCG phase A")
        for row in real_pcg:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"setup={row['t_setup_stub_s']:.3f}s ggm={row['t_ggm_pprf_s']:.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s check={row['t_consistency_check_s']:.3f}s "
                f"base={row['base_vole']} setup_comm={row['setup_comm_bytes']} B "
                f"{row['source']}"
            )
        print()
    real_pcg_b = report["real_pcg_spike"].get("real_pcg_phase_b") or []
    if real_pcg_b:
        print("Real-PCG phase B")
        for row in real_pcg_b:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"baseOT={row['t_base_ot_s']:.3f}s otExt={row['t_ot_extension_s']:.3f}s "
                f"ggm={(row['t_ggm_pprf_s'] or 0.0):.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s setup_comm={row['setup_comm_bytes']} B "
                f"production_ready={row['production_ready']} {row['source']}"
            )
        print()
    roofline = report.get("gpu_roofline", {}).get("run_of_record")
    if roofline:
        print("GPU Goldilocks/Fp2 roofline")
        print(
            f"  stream {roofline['stream_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['stream_gpu_bandwidth_gb_s']:.1f} GB/s; "
            f"chain {roofline['chain_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['chain_gpu_fp2_mul_s'] / 1e9:.2f} G Fp2-mul/s "
            f"{roofline['source']}"
        )
        print()
    fused = report.get("gpu_fused_epilogue", {}).get("run_of_record")
    if fused:
        shape_rhos = ", ".join(f"{row['n']}:{row['rho_kernel']:.3f}" for row in fused["shapes"])
        print("GPU fused GEMM-MAC epilogue")
        print(
            f"  weighted rho={fused['weighted_rho_kernel']:.3f}; "
            f"shape rhos [{shape_rhos}] {fused['source']}"
        )
        print()
    logup = report.get("gpu_logup_tree", {}).get("run_of_record")
    if logup:
        print("GPU LogUp fraction-tree build")
        print(
            f"  N={logup['parameters']['n']} CPU={logup['cpu_s']:.3f}s "
            f"GPU={logup['gpu_s']:.4f}s speedup={logup['gpu_cpu_speedup']:.2f}x "
            f"{logup['source']}"
        )
        print()
    logup_rounds = report.get("gpu_logup_rounds", {}).get("run_of_record")
    if logup_rounds:
        print("GPU LogUp general rounds/folds")
        print(
            f"  N={logup_rounds['parameters']['n']} CPU={logup_rounds['cpu_s']:.3f}s "
            f"GPU={logup_rounds['gpu_s']:.4f}s speedup={logup_rounds['gpu_cpu_speedup']:.2f}x "
            f"{logup_rounds['source']}"
        )
        print()
    blind_rounds = report.get("gpu_logup_blind_rounds", {}).get("run_of_record")
    if blind_rounds:
        print("GPU blind LogUp correction plumbing")
        print(
            f"  N={blind_rounds['parameters']['n']} CPU={blind_rounds['cpu_blind_s']:.3f}s "
            f"GPU={blind_rounds['gpu_blind_s']:.4f}s "
            f"speedup={blind_rounds['gpu_cpu_speedup']:.2f}x "
            f"blind/clear={blind_rounds['blind_over_clear']:.3f} "
            f"{blind_rounds['source']}"
        )
        print()
    pcs = report.get("gpu_pcs_arithmetic", {}).get("run_of_record")
    if pcs:
        print("GPU PCS arithmetic")
        print(
            f"  NTT {pcs['ntt']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['ntt']['gpu_s'] * 1e3:.2f} ms); combine_rows "
            f"{pcs['combine_rows']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['combine_rows']['gpu_s'] * 1e3:.2f} ms) {pcs['source']}"
        )
        print()
    blake3 = report.get("gpu_blake3_merkle", {}).get("run_of_record")
    if blake3:
        print("GPU PCS column gather + BLAKE3/Merkle")
        print(
            f"  {blake3['parameters']['rows']}x{blake3['parameters']['cols']} "
            f"Rust={blake3['rust_cpu_s'] * 1e3:.2f} ms "
            f"GPU={blake3['gpu_s'] * 1e3:.2f} ms "
            f"speedup={blake3['gpu_cpu_speedup']:.2f}x {blake3['source']}"
        )
        print()
    native_gpu = report.get("gpu_native_inference", {}).get("run_of_record")
    if native_gpu:
        targets = report["gpu_native_inference"]["required_prover_gpu_speedup_vs_cpu"]
        print("Native fixed-point GPU inference")
        print(
            f"  prefill={native_gpu['prefill_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['prefill']:.2f}x CPU); "
            f"decode50={native_gpu['decode_50_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['decode']:.2f}x CPU) {native_gpu['source']}"
        )
        if targets:
            print(
                f"  required integrated prover speedup vs CPU: "
                f"prefill {targets['prefill']:.2f}x, decode {targets['decode']:.2f}x"
            )
        print()
    hybrid = report.get("integrated_hybrid", {}).get("run_of_record")
    hybrid_rho = report.get("integrated_hybrid", {}).get("same_host_result")
    if hybrid:
        print("Integrated CUDA-hybrid prover")
        print(
            f"  proof prefill={hybrid['prove_prefill_s']:.3f}s; "
            f"decode marginal={hybrid['prove_decode_marginal_s']:.3f}s; "
            f"flat={hybrid['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(hybrid['packed_response_bytes']):.2f} MB {hybrid['source']}"
        )
        if hybrid_rho:
            measured = hybrid_rho["proof_rho"]
            gap = hybrid_rho["required_speedup_from_hybrid_to_target"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.2f}, "
                f"decode {measured['decode']:.2f}; resident gap to target "
                f"{gap['prefill']:.2f}x/{gap['decode']:.2f}x"
            )
        print()
    resident = report.get("integrated_resident", {}).get("run_of_record")
    resident_rho = report.get("integrated_resident", {}).get("same_host_result")
    if resident:
        cached_resident = resident.get("accelerator_cached_resident_device_bytes_after_cleanup")
        cached_resident_text = "n/a (schema<4)" if cached_resident is None else f"{cached_resident} B"
        trimmed_cached = resident.get("accelerator_cached_resident_device_bytes_after_cache_trim")
        trimmed_cached_text = "n/a (schema<4)" if trimmed_cached is None else f"{trimmed_cached} B"
        print("Integrated CUDA-resident prover")
        print(
            f"  proof core prefill={resident['prove_prefill_s']:.3f}s; "
            f"decode marginal={resident['prove_decode_marginal_s']:.3f}s; "
            f"online response={resident['prover_online_accounted_response_s']:.3f}s; "
            f"session wall={resident['response_session_wall_s']:.3f}s"
        )
        print(
            f"  flat={resident['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(resident['packed_response_bytes']):.2f} MB; "
            f"workspace after cleanup="
            f"{resident['accelerator_workspace_device_bytes_after_cleanup']} B; "
            f"cached resident after cleanup={cached_resident_text}; "
            f"explicit resident after cleanup="
            f"{resident['accelerator_resident_device_bytes_after_cleanup']} B; "
            f"cached resident after trim={trimmed_cached_text} "
            f"{resident['source']}"
        )
        accelerator_session = resident.get("accelerator_session") or {}
        if "resident_alloc_requests" in accelerator_session:
            print(
                f"  allocator: physical malloc={accelerator_session['allocation_calls']}; "
                f"logical alloc={accelerator_session['resident_alloc_requests']}; "
                f"reuse hits={accelerator_session['resident_reuse_hits']}; "
                f"logical free={accelerator_session['resident_free_requests']}; "
                f"physical free={accelerator_session['physical_free_calls']}"
            )
        if resident_rho:
            measured = resident_rho["proof_rho"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.3f} "
                f"({'PASS' if resident_rho['target_met']['prefill'] else 'FAIL'}); "
                f"decode {measured['decode']:.3f} "
                f"({'PASS' if resident_rho['target_met']['decode'] else 'FAIL'})"
            )
            pcs = resident_rho["pcs"]
            print(
                f"  PCS commit offline={pcs['commit_offline_s']:.3f}s; "
                f"open online={pcs['open_online_s']:.3f}s; verify={pcs['verify_s']:.3f}s; "
                f"PCG={resident_rho['pcg']['backend']} (production_grade=false)"
            )
        print()
    shape_sweep = report.get("shape_memory_sweep", {}).get("run_of_record")
    if shape_sweep:
        print("Synthetic shape/memory sweep (not non-GPT e2e)")
        for profile in shape_sweep["profiles"]:
            print(
                f"  {profile['name']:<30} total_i16="
                f"{profile['committed_weight_bytes_i16'] / 1e9:6.2f} GB "
                f"active_i16={profile['active_weight_bytes_i16'] / 1e9:6.2f} GB "
                f"GQA_KV={profile['gqa_kv_fraction_vs_mha']:.3f} "
                f"status={profile['status']}"
            )
        print(f"  {shape_sweep['source']}")
        print()
    decode_profiles = report.get("decode_marginal_profiles") or []
    if decode_profiles:
        print("Decode marginal profiles")
        for row in decode_profiles:
            print(
                f"  {row['milestone']:<8} {row['comm_decode_marginal_bytes']} B "
                f"({row['comm_decode_bytes_per_token']} B/token) {row['source']}"
            )
            for item in row["top_labels"][:5]:
                print(f"    {item['label']:<32} {item['bytes']}")
        print()
    print("PCS scenarios (packed response MB)")
    for row in report["pcs_scenarios"]:
        print(
            f"  {row['name']:<36} pcs={mb(row['pcs_opening_bytes']):7.2f} "
            f"total={mb(row['packed_response_download_bytes']):7.2f}  {row['status']}"
        )
    print()
    req = model["required_relative_prover_vs_native_speedup"]
    print("GPU rho sensitivity")
    print(f"  required relative prover/native speedup: prefill {req['prefill']:.2f}x, decode {req['decode']:.2f}x")
    for row in model["sensitivity"]:
        print(
            f"  rel={row['relative_prover_vs_native_speedup']:>4.1f}x "
            f"rho_prefill={row['rho_prefill']:>5.2f} "
            f"rho_decode={row['rho_decode']:>5.2f}"
        )
    print()
    print(f"recommendation: {report['go_no_go']['local_recommendation']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    ap.add_argument("--write-json", action="store_true", help="write benchmarks/results/p7-*.json")
    ap.add_argument(
        "--validate-p7b-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete official P7b verdict",
    )
    ap.add_argument(
        "--validate-fase-d-pod-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete fase-D G4 verdict",
    )
    ap.add_argument(
        "--validate-c3b-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete CPU or pod C3b verdict",
    )
    ap.add_argument(
        "--validate-t1-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete CPU or pod T1 verdict",
    )
    ap.add_argument(
        "--validate-x4-v4-cpu",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 CPU synthetic record",
    )
    ap.add_argument(
        "--validate-x4-v4-migration",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 GPT-2 migration reference",
    )
    ap.add_argument(
        "--validate-x4-v4-pod",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 A100 production verdict",
    )
    ap.add_argument(
        "--validate-x4d-codec-reference",
        type=Path,
        help="fail closed unless one JSON is the exact clean local X4d codec rebaseline",
    )
    ap.add_argument(
        "--validate-x4d-phase3-preflight",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4d pod hardware preflight",
    )
    ap.add_argument(
        "--validate-x4d-phase3-online",
        type=Path,
        help="fail closed unless one JSON is an internally complete X4d deferred-settlement verdict",
    )
    ap.add_argument(
        "--validate-x4d1-flatness",
        type=Path,
        help="fail closed unless one JSON is a complete paired X4d.1 flatness verdict",
    )
    ap.add_argument(
        "--x4d-onboarding",
        type=Path,
        help="explicit carried X4c onboarding record for --validate-x4d-phase3-online",
    )
    ap.add_argument(
        "--validate-x4b-local",
        type=Path,
        help="fail closed unless one JSON is the clean X4b local CPU/persisted-opening preflight",
    )
    ap.add_argument(
        "--validate-x4b-pod",
        type=Path,
        help="fail closed unless one JSON is an internally consistent X4b A100 verdict",
    )
    ap.add_argument(
        "--validate-x4c-phase1",
        type=Path,
        help="fail closed unless one JSON is the clean CPU-only X4c Phase-1 postdiction",
    )
    ap.add_argument(
        "--validate-x4c-legacy-causal",
        type=Path,
        help="fail closed unless one JSON is a complete X4c legacy causal diagnostic",
    )
    ap.add_argument(
        "--validate-x4c-lifecycle-probe",
        type=Path,
        help="fail closed unless one JSON is the exact 51.54-GB X4c lifecycle probe",
    )
    ap.add_argument(
        "--validate-x4c-onboarding",
        type=Path,
        help="fail closed unless one JSON is a complete schema-2 X4c onboarding record",
    )
    ap.add_argument(
        "--validate-x4c-online",
        type=Path,
        help="fail closed unless one JSON is a complete schema-2 X4c online record",
    )
    ap.add_argument(
        "--x4c-onboarding",
        type=Path,
        help="onboarding JSON whose exact SHA/source/cohorts must anchor --validate-x4c-online",
    )
    ap.add_argument(
        "--validate-x4c-gpt2-onboarding",
        type=Path,
        help="fail closed unless one JSON is a schema-2 real-weight X4c GPT-2 onboarding record",
    )
    ap.add_argument(
        "--validate-x4c-gpt2-online",
        type=Path,
        help="fail closed unless one JSON is a schema-2 real-weight X4c GPT-2 E2E record",
    )
    ap.add_argument(
        "--validate-x4c-gpt2-accelerated-online",
        type=Path,
        help=(
            "fail closed unless one JSON is the dedicated schema-2 accelerated "
            "real-weight X4c GPT-2 E2E record"
        ),
    )
    ap.add_argument(
        "--validate-x4c-gpt2-v3-onboarding",
        type=Path,
        help=(
            "fail closed unless one JSON is a schema-3 crypto-build-id "
            "real-weight X4c onboarding record"
        ),
    )
    ap.add_argument(
        "--validate-x4c-gpt2-v3-accelerated-online",
        type=Path,
        help=(
            "fail closed unless one JSON is a schema-3 crypto-build-id "
            "accelerated real-weight X4c E2E record"
        ),
    )
    ap.add_argument(
        "--write-x4c-gpt2-v3-validation-receipt",
        type=Path,
        help=(
            "append-only receipt path; requires the schema-3 accelerated "
            "online validator and a clean validator checkout"
        ),
    )
    ap.add_argument(
        "--x4c-gpt2-rebuild-admission",
        type=Path,
        help=(
            "append-only rebuild-admission marker anchoring the schema-3 "
            "accelerated online record"
        ),
    )
    ap.add_argument(
        "--validate-x4c-rebuild-preflight",
        type=Path,
        help=(
            "fail closed unless one JSON is a complete manual X4c accelerated "
            "rebuild preflight stage or diagnostic projection"
        ),
    )
    ap.add_argument(
        "--x4c-gpt2-onboarding",
        type=Path,
        help=(
            "exact onboarding JSON anchoring either real-weight X4c GPT-2 "
            "online validator"
        ),
    )
    args = ap.parse_args()

    selected_validators = sum(
        value is not None
        for value in (
            args.validate_p7b_official,
            args.validate_fase_d_pod_official,
            args.validate_c3b_official,
            args.validate_t1_official,
            args.validate_x4_v4_cpu,
            args.validate_x4_v4_migration,
            args.validate_x4_v4_pod,
            args.validate_x4d_codec_reference,
            args.validate_x4b_local,
            args.validate_x4b_pod,
            args.validate_x4c_phase1,
            args.validate_x4c_legacy_causal,
            args.validate_x4c_lifecycle_probe,
            args.validate_x4c_onboarding,
            args.validate_x4c_online,
            args.validate_x4c_gpt2_onboarding,
            args.validate_x4c_gpt2_online,
            args.validate_x4c_gpt2_accelerated_online,
            args.validate_x4c_gpt2_v3_onboarding,
            args.validate_x4c_gpt2_v3_accelerated_online,
            args.validate_x4c_rebuild_preflight,
        )
    )
    if selected_validators > 1:
        raise SystemExit("official validators are mutually exclusive")
    if (args.validate_x4c_online is None) != (args.x4c_onboarding is None):
        raise SystemExit(
            "--validate-x4c-online and --x4c-onboarding must be supplied together"
        )
    gpt2_online_selected = (
        args.validate_x4c_gpt2_online is not None
        or args.validate_x4c_gpt2_accelerated_online is not None
        or args.validate_x4c_gpt2_v3_accelerated_online is not None
    )
    if gpt2_online_selected == (args.x4c_gpt2_onboarding is None):
        raise SystemExit(
            "a real-weight X4c GPT-2 online validator and "
            "--x4c-gpt2-onboarding must be supplied together"
        )
    if (
        args.write_x4c_gpt2_v3_validation_receipt is not None
        and args.validate_x4c_gpt2_v3_accelerated_online is None
    ):
        raise SystemExit(
            "--write-x4c-gpt2-v3-validation-receipt requires "
            "--validate-x4c-gpt2-v3-accelerated-online"
        )
    if (
        args.validate_x4c_gpt2_v3_accelerated_online is None
    ) != (args.x4c_gpt2_rebuild_admission is None):
        raise SystemExit(
            "--validate-x4c-gpt2-v3-accelerated-online and "
            "--x4c-gpt2-rebuild-admission must be supplied together"
        )
    if args.validate_p7b_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-p7b-official are mutually exclusive")
        if not validate_p7b_official_result(args.validate_p7b_official):
            raise SystemExit("invalid or ineligible official P7b result")
        print(f"valid official P7b result: {args.validate_p7b_official}")
        return
    if args.validate_fase_d_pod_official is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-fase-d-pod-official are mutually exclusive"
            )
        if not validate_fase_d_pod_official_result(args.validate_fase_d_pod_official):
            raise SystemExit("invalid or ineligible official fase-D pod result")
        print(f"valid official fase-D pod result: {args.validate_fase_d_pod_official}")
        return
    if args.validate_c3b_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-c3b-official are mutually exclusive")
        if not validate_c3b_official_result(args.validate_c3b_official):
            raise SystemExit("invalid or ineligible official C3b result")
        print(f"valid official C3b result: {args.validate_c3b_official}")
        return
    if args.validate_t1_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-t1-official are mutually exclusive")
        if not validate_t1_official_result(args.validate_t1_official):
            raise SystemExit("invalid or ineligible official T1 result")
        print(f"valid official T1 result: {args.validate_t1_official}")
        return
    if args.validate_x4_v4_cpu is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4-v4-cpu are mutually exclusive")
        if not validate_x4_v4_cpu_result(args.validate_x4_v4_cpu):
            raise SystemExit("invalid or ineligible X4 v4 CPU synthetic result")
        print(f"valid X4 v4 CPU synthetic result: {args.validate_x4_v4_cpu}")
        return
    if args.validate_x4_v4_migration is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4-v4-migration are mutually exclusive"
            )
        if not validate_x4_v4_migration_result(args.validate_x4_v4_migration):
            raise SystemExit("invalid or ineligible X4 v4 GPT-2 migration result")
        print(f"valid X4 v4 GPT-2 migration result: {args.validate_x4_v4_migration}")
        return
    if args.validate_x4_v4_pod is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4-v4-pod are mutually exclusive")
        if not validate_x4_v4_pod_result(args.validate_x4_v4_pod):
            raise SystemExit("invalid or ineligible X4 v4 A100 production result")
        print(f"valid X4 v4 A100 production result: {args.validate_x4_v4_pod}")
        return
    if args.validate_x4d_codec_reference is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4d-codec-reference are mutually exclusive"
            )
        if not validate_x4d_codec_reference(args.validate_x4d_codec_reference):
            raise SystemExit("invalid or inconsistent X4d codec rebaseline")
        print(f"valid X4d codec rebaseline: {args.validate_x4d_codec_reference}")
        return
    if args.validate_x4d_phase3_preflight is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4d-phase3-preflight are mutually exclusive"
            )
        if not validate_x4d_phase3_preflight(args.validate_x4d_phase3_preflight):
            raise SystemExit("invalid or inconsistent X4d Phase-3 hardware preflight")
        print(f"valid X4d Phase-3 preflight: {args.validate_x4d_phase3_preflight}")
        return
    if args.validate_x4d_phase3_online is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4d-phase3-online are mutually exclusive"
            )
        if args.x4d_onboarding is None:
            raise SystemExit("--x4d-onboarding is required for X4d Phase-3 validation")
        if not validate_x4d_phase3_online(
            args.validate_x4d_phase3_online, args.x4d_onboarding
        ):
            raise SystemExit("invalid or inconsistent X4d Phase-3 online verdict")
        print(f"valid X4d Phase-3 online verdict: {args.validate_x4d_phase3_online}")
        return
    if args.validate_x4d1_flatness is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4d1-flatness are mutually exclusive"
            )
        if not validate_x4d1_flatness(args.validate_x4d1_flatness):
            raise SystemExit("invalid or inconsistent X4d.1 flatness verdict")
        print(f"valid X4d.1 flatness verdict: {args.validate_x4d1_flatness}")
        return
    if args.validate_x4b_local is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4b-local are mutually exclusive")
        if not validate_x4b_local_result(args.validate_x4b_local):
            raise SystemExit("invalid or ineligible X4b local preflight result")
        print(f"valid X4b local preflight result: {args.validate_x4b_local}")
        return
    if args.validate_x4b_pod is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4b-pod are mutually exclusive")
        if not validate_x4b_pod_result(args.validate_x4b_pod):
            raise SystemExit("invalid or inconsistent X4b A100 result")
        print(f"valid X4b A100 result: {args.validate_x4b_pod}")
        return
    if args.validate_x4c_phase1 is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4c-phase1 are mutually exclusive")
        if not validate_x4c_phase1_result(args.validate_x4c_phase1):
            raise SystemExit("invalid or inconsistent X4c Phase-1 result")
        print(f"valid X4c Phase-1 result: {args.validate_x4c_phase1}")
        return
    if args.validate_x4c_legacy_causal is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-legacy-causal are mutually exclusive"
            )
        if not validate_x4c_legacy_causal_result(args.validate_x4c_legacy_causal):
            raise SystemExit("invalid or inconsistent X4c legacy causal diagnostic")
        print(f"valid X4c legacy causal diagnostic: {args.validate_x4c_legacy_causal}")
        return
    if args.validate_x4c_lifecycle_probe is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-lifecycle-probe are mutually exclusive"
            )
        if not validate_x4c_lifecycle_probe_result(args.validate_x4c_lifecycle_probe):
            raise SystemExit("invalid or inconsistent X4c exact-size lifecycle probe")
        print(f"valid X4c exact-size lifecycle probe: {args.validate_x4c_lifecycle_probe}")
        return
    if args.validate_x4c_onboarding is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-onboarding are mutually exclusive"
            )
        if not validate_x4c_onboarding_result(args.validate_x4c_onboarding):
            raise SystemExit("invalid or inconsistent X4c onboarding record")
        print(f"valid X4c onboarding record: {args.validate_x4c_onboarding}")
        return
    if args.validate_x4c_online is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-online are mutually exclusive"
            )
        if not validate_x4c_online_result(
            args.validate_x4c_online, args.x4c_onboarding
        ):
            raise SystemExit("invalid or inconsistent X4c online/onboarding chain")
        print(
            f"valid X4c online/onboarding chain: {args.validate_x4c_online} "
            f"<- {args.x4c_onboarding}"
        )
        return
    if args.validate_x4c_gpt2_onboarding is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-gpt2-onboarding are mutually exclusive"
            )
        if not validate_x4c_gpt2_onboarding_result(
            args.validate_x4c_gpt2_onboarding
        ):
            raise SystemExit("invalid real-weight X4c GPT-2 onboarding record")
        print(
            "valid real-weight X4c GPT-2 onboarding record: "
            f"{args.validate_x4c_gpt2_onboarding}"
        )
        return
    if args.validate_x4c_gpt2_online is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-gpt2-online are mutually exclusive"
            )
        if not validate_x4c_gpt2_online_result(
            args.validate_x4c_gpt2_online, args.x4c_gpt2_onboarding
        ):
            raise SystemExit("invalid real-weight X4c GPT-2 online/onboarding chain")
        print(
            f"valid real-weight X4c GPT-2 chain: {args.validate_x4c_gpt2_online} "
            f"<- {args.x4c_gpt2_onboarding}"
        )
        return
    if args.validate_x4c_gpt2_accelerated_online is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-gpt2-accelerated-online "
                "are mutually exclusive"
            )
        if not validate_x4c_gpt2_accelerated_online_result(
            args.validate_x4c_gpt2_accelerated_online,
            args.x4c_gpt2_onboarding,
        ):
            raise SystemExit(
                "invalid accelerated real-weight X4c GPT-2 online/onboarding chain"
            )
        print(
            "valid accelerated real-weight X4c GPT-2 chain: "
            f"{args.validate_x4c_gpt2_accelerated_online} "
            f"<- {args.x4c_gpt2_onboarding}"
        )
        return
    if args.validate_x4c_gpt2_v3_onboarding is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-gpt2-v3-onboarding "
                "are mutually exclusive"
            )
        if not validate_x4c_gpt2_v3_onboarding_result(
            args.validate_x4c_gpt2_v3_onboarding
        ):
            raise SystemExit(
                "invalid schema-3 real-weight X4c GPT-2 onboarding record"
            )
        print(
            "valid schema-3 real-weight X4c GPT-2 onboarding record: "
            f"{args.validate_x4c_gpt2_v3_onboarding}"
        )
        return
    if args.validate_x4c_gpt2_v3_accelerated_online is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and "
                "--validate-x4c-gpt2-v3-accelerated-online "
                "are mutually exclusive"
            )
        if not validate_x4c_gpt2_v3_accelerated_online_result(
            args.validate_x4c_gpt2_v3_accelerated_online,
            args.x4c_gpt2_onboarding,
            args.x4c_gpt2_rebuild_admission,
        ):
            raise SystemExit(
                "invalid schema-3 accelerated real-weight X4c GPT-2 chain"
            )
        print(
            "valid schema-3 accelerated real-weight X4c GPT-2 chain: "
            f"{args.validate_x4c_gpt2_v3_accelerated_online} "
            f"<- {args.x4c_gpt2_onboarding}"
        )
        if args.write_x4c_gpt2_v3_validation_receipt is not None:
            receipt = write_x4c_gpt2_v3_validation_receipt(
                args.validate_x4c_gpt2_v3_accelerated_online,
                args.x4c_gpt2_onboarding,
                args.x4c_gpt2_rebuild_admission,
                args.write_x4c_gpt2_v3_validation_receipt,
            )
            print(f"wrote append-only schema-3 validation receipt: {receipt}")
        return
    if args.validate_x4c_rebuild_preflight is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4c-rebuild-preflight are mutually exclusive"
            )
        if not validate_x4c_rebuild_preflight_result(
            args.validate_x4c_rebuild_preflight
        ):
            raise SystemExit("invalid X4c accelerated rebuild preflight record")
        print(
            "valid X4c accelerated rebuild preflight record: "
            f"{args.validate_x4c_rebuild_preflight}"
        )
        return

    report = p7_report(args.results_dir)
    if not report["pcs_formula_check"]["matches_p6_measured_bytes"]:
        raise SystemExit("PCS byte formula does not match the P6 measured opening bytes")
    print_summary(report)
    if args.write_json:
        path = write_report(report, args.results_dir)
        print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()

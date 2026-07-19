#!/usr/bin/env python3
"""Analytic VOLTA-ZK response budget for dense and MoE transformer shapes.

This is a design-time shape model, not an end-to-end measurement.  It extends
``budget_p0.py`` to a prompt plus deferred-decode response and keeps the terms
that scale differently separate: native MACs, lookup instances, authenticated
boundary values, VOLE correlations, and PCS claims.

The default workload is the repository workload of record (100 prompt rows and
50 deferred decode rows).  Run, for example::

    python3 scripts/budget_moe.py
    python3 scripts/budget_moe.py --model gpt-oss-20b --json
    python3 scripts/budget_moe.py --prompt-tokens 512 --decode-tokens 128

Only the Python standard library is used.  All byte units printed as MB are
decimal, matching the response gates in the ledger.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable


FP_CORRECTION_BYTES = 8
DEFAULT_PROMPT_TOKENS = 100
DEFAULT_DECODE_TOKENS = 50
DEFAULT_THIN_K = 4
ARGMAX_TRANSCRIPT_BYTES_PER_TOKEN_REFERENCE = 57_840 / 50
PRODUCTION_CONNECTION_SUB_CAPACITY = 110_918_718
CHUNK_DOMAIN_CAP = 5
FLAT_COST_VALIDATED_CONTEXT = 150


def ceil_pow2(value: int) -> int:
    """Smallest power of two greater than or equal to a positive integer."""

    if value <= 0:
        raise ValueError("ceil_pow2 requires a positive integer")
    return 1 << (value - 1).bit_length()


def ceil_div(num: int, den: int) -> int:
    if den <= 0:
        raise ValueError("denominator must be positive")
    return (num + den - 1) // den


@dataclass(frozen=True)
class Workload:
    prompt_tokens: int = DEFAULT_PROMPT_TOKENS
    decode_tokens: int = DEFAULT_DECODE_TOKENS

    def __post_init__(self) -> None:
        if self.prompt_tokens <= 0:
            raise ValueError("prompt_tokens must be positive")
        if self.decode_tokens < 0:
            raise ValueError("decode_tokens must be non-negative")

    @property
    def transformer_rows(self) -> int:
        return self.prompt_tokens + self.decode_tokens

    @property
    def proof_phases(self) -> int:
        return 1 + int(self.decode_tokens > 0)

    @property
    def logit_rows(self) -> int:
        # A q-token response is selected by the prefill-final row followed by
        # q-1 decode rows.  The final decode state is retained for the cache,
        # but it does not require another logits matvec/output claim.
        return max(1, self.decode_tokens)

    @property
    def selected_token_rows(self) -> int:
        return self.decode_tokens

    def phases(self) -> tuple[tuple[str, int, int], ...]:
        rows: list[tuple[str, int, int]] = [("prefill", 0, self.prompt_tokens)]
        if self.decode_tokens:
            rows.append(("decode", self.prompt_tokens, self.decode_tokens))
        return tuple(rows)


@dataclass(frozen=True)
class ModelConfig:
    """Architecture and proof-layout inputs used by the analytic model.

    ``layer_windows`` contains ``None`` for full causal attention or a positive
    window length.  ``residual_requant_seams`` is deliberately explicit: until
    BF16/i16 calibration exists, the non-GPT profiles conservatively assume
    every inter-layer residual seam is a distinct requantized tensor.

    PCS claim counts are per proof phase.  A MoE expert has two independently
    evaluated blocks (fused gate/up and down); counting one claim for both
    would require a separately justified multi-point reduction.
    """

    name: str
    layers: int
    d_model: int
    d_ff: int
    n_heads: int
    n_kv_heads: int
    head_dim: int
    vocab: int
    layer_windows: tuple[int | None, ...]
    ffn_kind: str
    n_experts: int = 1
    top_k: int = 1
    clamp_swiglu: bool = False
    attention_sinks: int = 0
    residual_requant_seams: int = 0
    lookup_table_auth_values: int = 0
    private_argmax: bool = True
    argmax_u16_limbs: int = 3
    pcs_attention_claims_per_layer: int = 4
    pcs_dense_ffn_claims_per_layer: int = 3
    pcs_router_claims_per_layer: int = 0
    pcs_claims_per_expert: int = 0
    pcs_global_claims_per_phase: int = 2
    pcs_global_commitments: int = 1
    total_parameters: int | None = None
    active_parameters: int | None = None

    def __post_init__(self) -> None:
        positive = {
            "layers": self.layers,
            "d_model": self.d_model,
            "d_ff": self.d_ff,
            "n_heads": self.n_heads,
            "n_kv_heads": self.n_kv_heads,
            "head_dim": self.head_dim,
            "vocab": self.vocab,
            "n_experts": self.n_experts,
            "top_k": self.top_k,
            "argmax_u16_limbs": self.argmax_u16_limbs,
        }
        if any(value <= 0 for value in positive.values()):
            raise ValueError(f"positive ModelConfig fields required: {positive}")
        if len(self.layer_windows) != self.layers:
            raise ValueError("layer_windows must contain one entry per layer")
        if any(window is not None and window <= 0 for window in self.layer_windows):
            raise ValueError("attention windows must be positive or None")
        if self.n_heads % self.n_kv_heads:
            raise ValueError("GQA requires n_kv_heads to divide n_heads")
        if self.top_k > self.n_experts:
            raise ValueError("top_k cannot exceed n_experts")
        if not 0 <= self.residual_requant_seams < self.layers:
            raise ValueError("residual_requant_seams must lie in [0, layers)")
        if self.ffn_kind not in {"gelu", "swiglu"}:
            raise ValueError("ffn_kind must be 'gelu' or 'swiglu'")
        if self.n_experts == 1 and self.top_k != 1:
            raise ValueError("a dense profile must use top_k=1")
        if self.n_experts > 1 and self.pcs_claims_per_expert <= 0:
            raise ValueError("MoE profiles need a positive PCS expert-claim count")

    @property
    def q_dim(self) -> int:
        return self.n_heads * self.head_dim

    @property
    def kv_dim(self) -> int:
        return self.n_kv_heads * self.head_dim

    @property
    def is_moe(self) -> bool:
        return self.n_experts > 1

    @property
    def active_routes(self) -> int:
        return self.top_k if self.is_moe else 1

    @property
    def full_layers(self) -> int:
        return sum(window is None for window in self.layer_windows)

    @property
    def sliding_layers(self) -> int:
        return self.layers - self.full_layers


def llama_8b() -> ModelConfig:
    """Representative Llama-class 8B/GQA point pinned by the P7 sweep."""

    return ModelConfig(
        name="llama-class-8b-dense",
        layers=32,
        d_model=4096,
        d_ff=14_336,
        n_heads=32,
        n_kv_heads=8,
        head_dim=128,
        vocab=128_256,
        layer_windows=(None,) * 32,
        ffn_kind="swiglu",
        residual_requant_seams=31,
        # Provisional contents: rsqrt, exp, reciprocal, SiLU and shared
        # Range(16).  D4 calibration may add smaller shift-specific tables.
        lookup_table_auth_values=5 * (1 << 16),
        pcs_attention_claims_per_layer=4,
        pcs_dense_ffn_claims_per_layer=3,
        pcs_global_claims_per_phase=2,
        pcs_global_commitments=1,
        total_parameters=8_030_261_248,
        active_parameters=8_030_261_248,
    )


def gpt_oss_20b() -> ModelConfig:
    """Planning profile from scaling-note plus the published model config."""

    return ModelConfig(
        name="gpt-oss-20b",
        layers=24,
        d_model=2880,
        d_ff=2880,
        n_heads=64,
        n_kv_heads=8,
        head_dim=64,
        vocab=201_088,
        layer_windows=tuple(128 if layer % 2 == 0 else None for layer in range(24)),
        ffn_kind="swiglu",
        n_experts=32,
        top_k=4,
        clamp_swiglu=True,
        attention_sinks=4,
        residual_requant_seams=23,
        # Dense contents plus the clamped-SwiGLU saturation table.  Router
        # range checks reuse the shared Range(16) content.
        lookup_table_auth_values=6 * (1 << 16),
        pcs_attention_claims_per_layer=4,
        pcs_dense_ffn_claims_per_layer=0,
        pcs_router_claims_per_layer=1,
        pcs_claims_per_expert=2,
        pcs_global_claims_per_phase=2,
        pcs_global_commitments=1,
        total_parameters=20_900_000_000,
        active_parameters=3_600_000_000,
    )


def gpt2_c1_anchor(private_argmax: bool = False) -> ModelConfig:
    """Measured C1 shape used only to audit the accounting equations."""

    return ModelConfig(
        name="gpt2-c1-anchor",
        layers=12,
        d_model=768,
        d_ff=3072,
        n_heads=12,
        n_kv_heads=12,
        head_dim=64,
        vocab=50_257,
        layer_windows=(None,) * 12,
        ffn_kind="gelu",
        residual_requant_seams=2,
        # Exact remainder derived from the C1 correction stream after the
        # structural small-vector terms below; it is the model-wide shared
        # TableBank multiplicity authentication count for the frozen tables.
        lookup_table_auth_values=355_902,
        private_argmax=private_argmax,
        pcs_attention_claims_per_layer=2,  # fused c_attn + c_proj
        pcs_dense_ffn_claims_per_layer=2,
        pcs_global_claims_per_phase=3,
        pcs_global_commitments=1,
        total_parameters=124_000_000,
        active_parameters=124_000_000,
    )


def phase_attention_pairs(t0: int, q: int, window: int | None) -> int:
    """Real token-key pairs for q query rows beginning at absolute t0."""

    if q < 0 or t0 < 0:
        raise ValueError("attention phase dimensions must be non-negative")
    if window is None:
        return q * (2 * t0 + q + 1) // 2
    return sum(min(t0 + row + 1, window) for row in range(q))


def attention_budget(config: ModelConfig, workload: Workload) -> dict[str, Any]:
    by_schedule: dict[str, dict[str, int]] = {}
    per_layer: list[dict[str, Any]] = []
    total_token_pairs = 0
    total_head_pairs = 0
    for layer, window in enumerate(config.layer_windows):
        label = "full" if window is None else f"sliding-{window}"
        row = {"layer": layer, "schedule": label}
        layer_pairs = 0
        for phase, t0, q in workload.phases():
            pairs = phase_attention_pairs(t0, q, window)
            row[f"{phase}_token_pairs"] = pairs
            layer_pairs += pairs
            target = by_schedule.setdefault(label, {"layers": 0, "token_pairs": 0})
            target["token_pairs"] += pairs
        by_schedule[label]["layers"] += 1
        row["response_token_pairs"] = layer_pairs
        per_layer.append(row)
        total_token_pairs += layer_pairs
        total_head_pairs += config.n_heads * layer_pairs
    return {
        "by_schedule": by_schedule,
        "per_layer": per_layer,
        "token_pairs_all_layers": total_token_pairs,
        "query_head_pairs_all_layers": total_head_pairs,
    }


def native_mac_budget(config: ModelConfig, workload: Workload) -> dict[str, Any]:
    rows = workload.transformer_rows
    d, qd, kd = config.d_model, config.q_dim, config.kv_dim
    macs: dict[str, int] = {
        "q_proj": config.layers * rows * d * qd,
        "k_proj": config.layers * rows * d * kd,
        "v_proj": config.layers * rows * d * kd,
        "attention_qk": 0,
        "attention_av": 0,
        "attention_out_proj": config.layers * rows * qd * d,
    }
    for window in config.layer_windows:
        pairs = sum(phase_attention_pairs(t0, q, window) for _, t0, q in workload.phases())
        one_leg = config.n_heads * pairs * config.head_dim
        macs["attention_qk"] += one_leg
        macs["attention_av"] += one_leg
    if config.ffn_kind == "gelu":
        macs["ffn_up"] = config.layers * rows * d * config.d_ff
        macs["ffn_down"] = config.layers * rows * config.d_ff * d
    else:
        routes = config.active_routes
        macs["ffn_gate_up"] = config.layers * rows * routes * d * (2 * config.d_ff)
        macs["ffn_down"] = config.layers * rows * routes * config.d_ff * d
    if config.is_moe:
        macs["router"] = config.layers * rows * d * config.n_experts
    macs["logits"] = workload.logit_rows * d * config.vocab
    total = sum(macs.values())
    return {
        "by_op": macs,
        "total": total,
        "total_gmac": total / 1e9,
        "macs_per_transformer_row": total / rows,
    }


class LookupAccumulator:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, int]] = {}
        self._site_lengths: list[int] = []

    def add(self, op: str, logical: int, *, padded: int | None = None) -> None:
        if logical <= 0:
            return
        domain = padded if padded is not None else ceil_pow2(logical)
        if domain < logical or domain & (domain - 1):
            raise ValueError("lookup padded domain must be a covering power of two")
        row = self._rows.setdefault(op, {"logical": 0, "padded": 0, "sites": 0})
        row["logical"] += logical
        row["padded"] += domain
        row["sites"] += 1
        self._site_lengths.append(domain)

    @property
    def rows(self) -> dict[str, dict[str, int]]:
        return dict(sorted(self._rows.items()))

    @property
    def logical_total(self) -> int:
        return sum(row["logical"] for row in self._rows.values())

    @property
    def padded_total(self) -> int:
        return sum(row["padded"] for row in self._rows.values())

    @property
    def site_count(self) -> int:
        return len(self._site_lengths)

    @property
    def log_rounds(self) -> int:
        return sum(domain.bit_length() - 1 for domain in self._site_lengths)


def balanced_bucket_sizes(total: int, buckets: int) -> tuple[int, ...]:
    """Deterministic balanced integer split used for MoE padding projections."""

    if total < 0 or buckets <= 0:
        raise ValueError("invalid balanced-bucket dimensions")
    base, extra = divmod(total, buckets)
    return tuple(base + int(index < extra) for index in range(buckets))


def lookup_budget(config: ModelConfig, workload: Workload) -> dict[str, Any]:
    layer_acc = LookupAccumulator()
    global_acc = LookupAccumulator()
    d, qd, kd = config.d_model, config.q_dim, config.kv_dim

    for window in config.layer_windows:
        for _, t0, q in workload.phases():
            pairs = phase_attention_pairs(t0, q, window)
            layer_acc.add("norm_rsqrt", 2 * q)
            layer_acc.add("norm_requant", 2 * q * d)
            layer_acc.add("requant_qkv", q * (qd + 2 * kd))
            layer_acc.add("requant_scores", config.n_heads * pairs)
            layer_acc.add(
                "attention_exp",
                config.n_heads * (pairs + q * config.attention_sinks),
            )
            layer_acc.add("softmax_recip", config.n_heads * q)
            layer_acc.add("softmax_norm_requant", config.n_heads * pairs)
            layer_acc.add("requant_av", q * qd)
            layer_acc.add("requant_attention_out", q * d)

            if config.is_moe:
                layer_acc.add("router_requant", q * config.n_experts)
                layer_acc.add("router_exp", q * config.n_experts)
                layer_acc.add("router_recip", q)
                layer_acc.add("router_topk_range", q * config.n_experts)

            routes = config.active_routes
            if config.ffn_kind == "gelu":
                layer_acc.add("requant_ffn_up", q * config.d_ff)
                layer_acc.add("gelu", q * config.d_ff)
                layer_acc.add("requant_ffn_down", q * d)
            elif not config.is_moe:
                layer_acc.add("requant_ffn_gate_up", q * routes * 2 * config.d_ff)
                layer_acc.add("silu", q * routes * config.d_ff)
                if config.clamp_swiglu:
                    # gate has an upper clamp; up has lower and upper clamps.
                    # Both are represented by one saturation-table entry per
                    # element.  The ensuing Hadamard relation is Π_Prod, not a
                    # lookup, and is therefore intentionally absent here.
                    layer_acc.add("swiglu_clamp", q * routes * 2 * config.d_ff)
                layer_acc.add("requant_ffn_down", q * routes * d)
            else:
                # X2's public gather produces per-expert GEMMs.  The exact
                # public route histogram is not known at X0, so split q*top_k
                # assignments as evenly as possible and pad every expert job
                # separately.  Logical totals remain exact under any routing.
                for expert_rows in balanced_bucket_sizes(q * routes, config.n_experts):
                    layer_acc.add("requant_ffn_gate_up", expert_rows * 2 * config.d_ff)
                    layer_acc.add("silu", expert_rows * config.d_ff)
                    if config.clamp_swiglu:
                        layer_acc.add("swiglu_clamp", expert_rows * 2 * config.d_ff)
                    layer_acc.add("requant_ffn_down", expert_rows * d)
            if config.is_moe:
                layer_acc.add("moe_combine_requant", q * d)

    for _, _, q in workload.phases():
        global_acc.add("embedding_requant", q * d)
    final_rows = workload.logit_rows
    global_acc.add("final_norm_rsqrt", final_rows)
    global_acc.add("final_norm_requant", final_rows * d)
    if config.residual_requant_seams:
        for _, _, q in workload.phases():
            global_acc.add(
                "residual_seam_requant",
                config.residual_requant_seams * q * d,
            )

    if config.private_argmax and workload.selected_token_rows:
        # C3b packs five public positions into one segment per limb.  Retain
        # that scheduling rule for the shape projection; it is not an X1-X3
        # implementation claim.
        group = 5
        remaining = workload.selected_token_rows
        while remaining:
            positions = min(group, remaining)
            logical = positions * config.vocab
            for _ in range(config.argmax_u16_limbs):
                global_acc.add("private_argmax_range", logical)
            remaining -= positions

    by_op = layer_acc.rows
    for op, row in global_acc.rows.items():
        if op in by_op:
            merged = by_op[op]
            by_op[op] = {key: merged[key] + row[key] for key in merged}
        else:
            by_op[op] = row
    logical = layer_acc.logical_total + global_acc.logical_total
    padded = layer_acc.padded_total + global_acc.padded_total
    return {
        "by_op": dict(sorted(by_op.items())),
        "layer_core_logical_total": layer_acc.logical_total,
        "global_logical_total": global_acc.logical_total,
        "logical_total": logical,
        "padded_total": padded,
        "padding_ratio": padded / logical,
        "site_count": layer_acc.site_count + global_acc.site_count,
        "log_rounds": layer_acc.log_rounds + global_acc.log_rounds,
    }


def _other_auth_components(config: ModelConfig, workload: Workload) -> dict[str, int]:
    d = config.d_model
    components: dict[str, int] = {
        # The embedding proof authenticates its output separately from the
        # layer-0 x_in reader, exactly as in the current response plumbing.
        "embedding_output": workload.transformer_rows * d,
        "layer_norm_stats": 0,
        "attention_row_tables": 0,
        "attention_mask_accumulators": 0,
        "final_norm_and_input": 0,
        "lookup_multiplicities": config.lookup_table_auth_values,
        "attention_sinks": (
            config.layers
            * workload.proof_phases
            * config.n_heads
            * config.attention_sinks
        ),
        "private_argmax_selected_rows": 0,
    }
    head_pad = ceil_pow2(config.n_heads)
    for _, _, q in workload.phases():
        q_pad = ceil_pow2(q)
        # Two normalizations per layer; mean/var/rsqrt-in/rsqrt-out are four
        # padded vectors each.  RMSNorm is a subset, so this is conservative.
        components["layer_norm_stats"] += config.layers * 2 * 4 * q_pad
        # denoms, reciprocal inputs, reciprocals and stable-softmax row shift.
        components["attention_row_tables"] += config.layers * 4 * head_pad * q_pad
        # Only future positions within a proof chunk are materialized.  A
        # sliding-window lower edge is a public BandShape selector and does
        # not authenticate the old prefix that lies outside the rectangle.
        components["attention_mask_accumulators"] += (
            config.layers * config.n_heads * q * (q - 1) // 2
        )

    # Prefill final-LN uses the current duplicated two-row binding: two output
    # rows, two input rows and four two-entry statistic vectors.
    components["final_norm_and_input"] += 4 * d + 8
    if workload.decode_tokens:
        # Deferred decode proves q final outputs and four q-padded statistics;
        # the input is the already-bound final residual stream.
        components["final_norm_and_input"] += (
            workload.decode_tokens * d + 4 * ceil_pow2(workload.decode_tokens)
        )
    if config.private_argmax and workload.selected_token_rows:
        components["private_argmax_selected_rows"] = ceil_pow2(
            workload.selected_token_rows
        )
    return components


def authenticated_value_budget(
    config: ModelConfig, workload: Workload, thin_k: int = DEFAULT_THIN_K
) -> dict[str, Any]:
    if thin_k <= 0:
        raise ValueError("thin_k must be positive")
    rows, d = workload.transformer_rows, config.d_model

    # Current plumbing authenticates attention and FFN block outputs plus a
    # fresh x_in for layer 0 and every non-identity residual requant seam.
    residual_current = (
        2 * config.layers + 1 + config.residual_requant_seams
    ) * rows * d
    # T1 keeps each chunk entry and the exit of each k-layer fused chain.
    residual_thinned = (1 + ceil_div(config.layers, thin_k)) * rows * d
    kv = 2 * config.layers * rows * config.kv_dim
    other_components = _other_auth_components(config, workload)
    other = sum(other_components.values())
    current_total = residual_current + kv + other
    thinned_total = residual_thinned + kv + other
    return {
        "current": {
            "residual": residual_current,
            "kv_cache": kv,
            "other": other,
            "total": current_total,
            "correction_bytes": current_total * FP_CORRECTION_BYTES,
        },
        f"thin_k{thin_k}": {
            "residual": residual_thinned,
            "kv_cache": kv,
            "other": other,
            "total": thinned_total,
            "correction_bytes": thinned_total * FP_CORRECTION_BYTES,
        },
        "other_components": other_components,
        "saving_values": current_total - thinned_total,
        "saving_bytes": (current_total - thinned_total) * FP_CORRECTION_BYTES,
        "kv_share_of_current": kv / current_total,
        "kv_share_of_thinned": kv / thinned_total,
        "formula": {
            "residual_current": "(2*L + 1 + distinct_requant_seams) * T * d",
            "residual_thinned": "(1 + ceil(L/k)) * T * d",
            "kv_cache": "2 * L * T * n_kv_heads * head_dim",
            "correction_bytes": "8 * authenticated_values (F_p corrections)",
        },
    }


def expected_distinct_experts(config: ModelConfig, tokens: int) -> float:
    if not config.is_moe:
        return 0.0
    idle = (1 - config.top_k / config.n_experts) ** tokens
    return config.n_experts * (1 - idle)


def pcs_budget(config: ModelConfig, workload: Workload) -> dict[str, Any]:
    fixed_layer_claims = (
        config.pcs_attention_claims_per_layer
        + config.pcs_dense_ffn_claims_per_layer
        + config.pcs_router_claims_per_layer
    )
    upper_per_phase = config.layers * (
        fixed_layer_claims + config.n_experts * config.pcs_claims_per_expert
    ) + config.pcs_global_claims_per_phase
    upper_response = workload.proof_phases * upper_per_phase

    expected_response = 0.0
    phase_rows: list[dict[str, Any]] = []
    for phase, _, q in workload.phases():
        touched = expected_distinct_experts(config, q)
        claims = config.layers * (
            fixed_layer_claims + touched * config.pcs_claims_per_expert
        ) + config.pcs_global_claims_per_phase
        if not config.is_moe:
            # Dense configurations have no expert-block claims.
            claims = config.layers * fixed_layer_claims + config.pcs_global_claims_per_phase
        phase_rows.append(
            {
                "phase": phase,
                "tokens": q,
                "expected_distinct_experts_per_layer": touched,
                "expected_claims": claims,
            }
        )
        expected_response += claims

    return {
        "commitments": config.layers + config.pcs_global_commitments,
        "claims_per_phase_upper": upper_per_phase,
        "claims_per_response_stacked_upper": upper_response,
        "claims_per_response_expected": expected_response,
        "phase_expectations": phase_rows,
        "one_batched_opening_per_response": True,
        "claim_assumption": (
            "one claim per independently evaluated tensor block per prefill/decode "
            "phase; two claims per MoE expert (fused gate/up and down)"
        ),
    }


def correlation_budget(
    config: ModelConfig,
    workload: Workload,
    auth: dict[str, Any],
    lookups: dict[str, Any],
    pcs: dict[str, Any],
    thin_k: int,
) -> dict[str, Any]:
    # Subfield correlations are exact under the analytic correction schedule:
    # one fresh F_p mask for every authenticated value.  Full-field masks are
    # scheduler-dependent before X1-X3 exist.  Expose a transparent planning
    # proxy rather than pretending it is allocation-digest exact.
    logup_proxy = 3 * (8 * lookups["log_rounds"] + 12 * lookups["site_count"])
    pcs_proxy = 2 * math.ceil(pcs["claims_per_response_stacked_upper"])
    chain_proxy = 32 * config.layers * workload.proof_phases
    full_proxy = logup_proxy + pcs_proxy + chain_proxy
    return {
        "subfield_current_exact": auth["current"]["total"],
        f"subfield_thin_k{thin_k}_exact": auth[f"thin_k{thin_k}"]["total"],
        "full_field_planning_proxy": full_proxy,
        "full_field_proxy_terms": {
            "logup_round_masks": logup_proxy,
            "pcs_claim_masks": pcs_proxy,
            "chain_and_closure_masks": chain_proxy,
        },
        "full_field_proxy_is_gate_eligible": False,
        "note": (
            "full-field use must be replaced by exact allocation-digest counters "
            "when the non-GPT proof schedule exists"
        ),
    }


def long_output_budget(
    config: ModelConfig,
    workload: Workload,
    thin_k: int,
    auth: dict[str, Any],
) -> dict[str, Any]:
    prompt_only = Workload(workload.prompt_tokens, 0)
    prompt_auth = authenticated_value_budget(config, prompt_only, thin_k)
    next_workload = Workload(workload.prompt_tokens, workload.decode_tokens + 1)
    next_auth = authenticated_value_budget(config, next_workload, thin_k)
    decode = workload.decode_tokens

    average_current = None
    average_thinned = None
    if decode:
        average_current = (
            auth["current"]["correction_bytes"]
            - prompt_auth["current"]["correction_bytes"]
        ) / decode
        average_thinned = (
            auth[f"thin_k{thin_k}"]["correction_bytes"]
            - prompt_auth[f"thin_k{thin_k}"]["correction_bytes"]
        ) / decode

    mac_now = native_mac_budget(config, workload)["total"]
    mac_next = native_mac_budget(config, next_workload)["total"]
    next_context = workload.transformer_rows + 1
    full_pairs = next_context
    sliding_pairs = {
        str(window): min(next_context, window)
        for window in sorted({w for w in config.layer_windows if w is not None})
    }
    average_auth_per_processed_token = auth["current"]["total"] / workload.transformer_rows
    return {
        "average_decode_correction_bytes_current": average_current,
        f"average_decode_correction_bytes_thin_k{thin_k}": average_thinned,
        "next_decode_correction_bytes_current": (
            next_auth["current"]["correction_bytes"]
            - auth["current"]["correction_bytes"]
        ),
        f"next_decode_correction_bytes_thin_k{thin_k}": (
            next_auth[f"thin_k{thin_k}"]["correction_bytes"]
            - auth[f"thin_k{thin_k}"]["correction_bytes"]
        ),
        "argmax_transcript_bytes_per_generated_token_reference": (
            ARGMAX_TRANSCRIPT_BYTES_PER_TOKEN_REFERENCE
        ),
        "next_decode_native_macs": mac_next - mac_now,
        "next_decode_attention_token_pairs_per_full_layer": full_pairs,
        "next_decode_attention_token_pairs_per_sliding_layer": sliding_pairs,
        "native_and_prover_context_shape": (
            "linear in context for each full-attention decode layer; bounded by "
            "the window for sliding layers"
        ),
        "production_connection_sub_capacity": PRODUCTION_CONNECTION_SUB_CAPACITY,
        "connection_token_equivalents_at_current_average": (
            PRODUCTION_CONNECTION_SUB_CAPACITY / average_auth_per_processed_token
        ),
        "chunk_domain_cap": CHUNK_DOMAIN_CAP,
        "flat_cost_validated_only_to_context": FLAT_COST_VALIDATED_CONTEXT,
    }


def model_report(config: ModelConfig, workload: Workload, thin_k: int) -> dict[str, Any]:
    attention = attention_budget(config, workload)
    macs = native_mac_budget(config, workload)
    lookups = lookup_budget(config, workload)
    auth = authenticated_value_budget(config, workload, thin_k)
    pcs = pcs_budget(config, workload)
    correlations = correlation_budget(config, workload, auth, lookups, pcs, thin_k)
    long_output = long_output_budget(config, workload, thin_k, auth)
    weights = None
    if config.total_parameters is not None:
        active_parameters = config.active_parameters or config.total_parameters
        weights = {
            "total_parameters": config.total_parameters,
            "active_parameters": active_parameters,
            "active_fraction": active_parameters / config.total_parameters,
            "committed_i16_bytes": 2 * config.total_parameters,
            "active_i16_bytes": 2 * active_parameters,
        }
    return {
        "config": asdict(config),
        "weights": weights,
        "attention": attention,
        "native_macs": macs,
        "authenticated_values": auth,
        "lookups": lookups,
        "correlations": correlations,
        "pcs": pcs,
        "long_output": long_output,
        "scope": {
            "analytic_projection_only": True,
            "non_gpt_end_to_end": False,
            "proof_time_projected": False,
            "response_total_projected": False,
            "reason_response_total_omitted": (
                "X4 folding-PCS opening bytes and a measured non-GPT transcript do not exist"
            ),
        },
    }


def run_self_checks(thin_k: int = DEFAULT_THIN_K) -> dict[str, Any]:
    p0 = Workload(100, 0)
    c1 = Workload(100, 50)
    anchor = gpt2_c1_anchor(private_argmax=False)
    p0_macs = native_mac_budget(anchor, p0)["total"]
    p0_lookups = lookup_budget(anchor, p0)["layer_core_logical_total"]
    c1_auth = authenticated_value_budget(anchor, c1, thin_k)
    c3b_auth = authenticated_value_budget(
        replace(anchor, private_argmax=True), c1, thin_k
    )
    full_pairs = phase_attention_pairs(0, 100, None) + phase_attention_pairs(100, 50, None)

    checks = {
        "p0_native_macs_8_625_144_576": p0_macs == 8_625_144_576,
        "p0_layer_lookup_count_16_944_000": p0_lookups == 16_944_000,
        "attention_pairs_5050_plus_6275": full_pairs == 11_325,
        "c1_residual_split_3_110_400": c1_auth["current"]["residual"] == 3_110_400,
        "c1_kv_split_2_764_800": c1_auth["current"]["kv_cache"] == 2_764_800,
        "c1_other_split_1_567_926": c1_auth["current"]["other"] == 1_567_926,
        "c1_total_sub_corrs_7_443_126": c1_auth["current"]["total"] == 7_443_126,
        "c1_auth_corrections_59_545_008": (
            c1_auth["current"]["correction_bytes"] == 59_545_008
        ),
        "c3b_selected_rows_add_512_bytes": (
            c3b_auth["current"]["correction_bytes"] == 59_545_520
        ),
    }
    if thin_k == 4:
        checks["c3b_k4_projection_38_348_720_bytes"] = (
            c3b_auth["thin_k4"]["correction_bytes"] == 38_348_720
        )
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise AssertionError(f"budget self-check failure: {failed}")
    return {
        "all_pass": True,
        "checks": checks,
        "c1_measured_split": {
            "residual": c1_auth["current"]["residual"],
            "kv_cache": c1_auth["current"]["kv_cache"],
            "other": c1_auth["current"]["other"],
            "total": c1_auth["current"]["total"],
        },
        "t1_c3b_anchor": {
            "measured_response_bytes": 105_717_632,
            "measured_correction_bytes": c3b_auth["current"]["correction_bytes"],
            f"projected_correction_bytes_thin_k{thin_k}": c3b_auth[f"thin_k{thin_k}"][
                "correction_bytes"
            ],
            f"projected_response_bytes_thin_k{thin_k}_before_eq_reduction_overhead": (
                105_717_632
                - c3b_auth["current"]["correction_bytes"]
                + c3b_auth[f"thin_k{thin_k}"]["correction_bytes"]
            ),
            "clears_75_000_000_byte_desideratum": (
                105_717_632
                - c3b_auth["current"]["correction_bytes"]
                + c3b_auth[f"thin_k{thin_k}"]["correction_bytes"]
                <= 75_000_000
            ),
            "projection_condition": (
                "only the measured residual seam category changes; KV and all "
                "other C3b response bytes remain fixed; this is before the "
                "amended multi-point eq-sumcheck reduction transcript overhead"
            ),
        },
    }


ASSUMPTIONS = [
    "All counts are analytic shape projections; no Llama/gpt-oss frontend or e2e proof is claimed.",
    "Corrections remain F_p-typed at 8 bytes; Packed16 is not credited.",
    "gpt-oss MXFP4 expert weights are budgeted after offline dequantization to calibrated i16; no 4-bit proof-semantic saving is credited.",
    "Non-GPT D4 calibration is pending, so every inter-layer residual seam is conservatively distinct before thinning.",
    "T1 k-layer chains keep every chunk entry and every chain exit; K/V auth and the 'other' stream are unchanged.",
    "GQA authenticates only n_kv_heads*head_dim K/V values, while attention QK/AV work uses all query heads.",
    "Sliding attention uses a public lower-edge BandShape; old positions outside the window are not authenticated mask cells.",
    "MoE routes are balanced for padded lookup sizing; expert-touch expectations use independent uniform top-k routing only as a cost model.",
    "MoE PCS uses two claims per touched expert per phase (fused gate/up and down); no unsound cross-point RLC saving is assumed.",
    "Lookup padding is one power-of-two instance per (layer, phase, op), split per expert for MoE, with five-position C3b-style packing for private argmax.",
    "Full-field correlation use is a labeled planning proxy until an exact X1-X3 allocation schedule and digest exist.",
    "No total response byte is projected: the per-response PCS opening remains the X4 folding-PCS deliverable.",
]


def build_report(
    configs: Iterable[ModelConfig], workload: Workload, thin_k: int
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "workload": asdict(workload),
        "thin_k": thin_k,
        "models": {
            config.name: model_report(config, workload, thin_k) for config in configs
        },
        "self_checks": run_self_checks(thin_k),
        "assumptions": ASSUMPTIONS,
    }


def fmt_int(value: int | float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.0f}"


def fmt_mb(value: int | float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value / 1e6:,.3f} MB"


def print_report(report: dict[str, Any]) -> None:
    workload = report["workload"]
    thin_k = report["thin_k"]
    print(
        "VOLTA-ZK analytic X0 budget — "
        f"prompt={workload['prompt_tokens']}, decode={workload['decode_tokens']}, k={thin_k}"
    )
    print("Scope: analytic only; no non-GPT e2e or total-response measurement.\n")
    for name, model in report["models"].items():
        cfg = model["config"]
        print(f"== {name} ==")
        print(
            "shape: "
            f"L={cfg['layers']}, d={cfg['d_model']}, d_ff={cfg['d_ff']}, "
            f"heads={cfg['n_heads']}/{cfg['n_kv_heads']}, experts={cfg['n_experts']} "
            f"top-{cfg['top_k']}, vocab={cfg['vocab']:,}"
        )
        if model["weights"] is not None:
            weights = model["weights"]
            print(
                f"weights: total={weights['total_parameters']:,}, active={weights['active_parameters']:,}, "
                f"committed i16={fmt_mb(weights['committed_i16_bytes'])}"
            )
        schedules = model["attention"]["by_schedule"]
        print("attention token pairs (before query-head expansion):")
        for schedule, row in schedules.items():
            print(
                f"  {schedule:<14} layers={row['layers']:>2}  "
                f"response pairs={row['token_pairs']:>12,}"
            )

        print(f"native MACs: {model['native_macs']['total']:,} ({model['native_macs']['total_gmac']:,.3f} G)")
        for op, count in model["native_macs"]["by_op"].items():
            print(f"  {op:<28}{count:>20,}")

        auth = model["authenticated_values"]
        print("authenticated values / F_p correction stream:")
        for label in ("current", f"thin_k{thin_k}"):
            row = auth[label]
            print(
                f"  {label:<10} residual={row['residual']:>12,}  "
                f"KV={row['kv_cache']:>12,}  other={row['other']:>12,}  "
                f"total={row['total']:>12,}  {fmt_mb(row['correction_bytes'])}"
            )
        print(
            f"  k={thin_k} saving: {auth['saving_values']:,} values / "
            f"{fmt_mb(auth['saving_bytes'])}; KV share after={auth[f'thin_k{thin_k}']['kv_cache']/auth[f'thin_k{thin_k}']['total']:.2%}"
        )

        lookups = model["lookups"]
        print(
            f"lookups: logical={lookups['logical_total']:,}, padded={lookups['padded_total']:,}, "
            f"ratio={lookups['padding_ratio']:.4f}, sites={lookups['site_count']:,}"
        )
        for op, row in lookups["by_op"].items():
            print(
                f"  {op:<28}{row['logical']:>14,} logical  "
                f"{row['padded']:>14,} padded  ({row['sites']:>3} sites)"
            )

        pcs = model["pcs"]
        print(
            "PCS: "
            f"commitments={pcs['commitments']:,}, "
            f"stacked claims upper={pcs['claims_per_response_stacked_upper']:,}, "
            f"expected={pcs['claims_per_response_expected']:,.2f}"
        )
        correlations = model["correlations"]
        print(
            "correlations: "
            f"sub current={correlations['subfield_current_exact']:,}, "
            f"sub k={thin_k}={correlations[f'subfield_thin_k{thin_k}_exact']:,}, "
            f"full-field proxy={correlations['full_field_planning_proxy']:,} (non-gating)"
        )
        long = model["long_output"]
        print(
            "long-output marginal: "
            f"avg decode corrections current={fmt_mb(long['average_decode_correction_bytes_current'])}/token, "
            f"k={thin_k}={fmt_mb(long[f'average_decode_correction_bytes_thin_k{thin_k}'])}/token"
        )
        print(
            "  next-token corrections: "
            f"current={fmt_mb(long['next_decode_correction_bytes_current'])}, "
            f"k={thin_k}={fmt_mb(long[f'next_decode_correction_bytes_thin_k{thin_k}'])}; "
            f"native MACs={long['next_decode_native_macs']:,}"
        )
        print(
            "  connection capacity at this average: "
            f"{long['connection_token_equivalents_at_current_average']:,.1f} processed-token equivalents; "
            f"argmax ref={long['argmax_transcript_bytes_per_generated_token_reference']:,.1f} B/generated token"
        )
        print()

    anchor = report["self_checks"]["t1_c3b_anchor"]
    print("Self-checks: PASS (P0 MAC/lookups, C1 split/bytes, C3b +512 B).")
    print(
        f"C3b T1 anchor at k={thin_k}: corrections "
        f"{anchor[f'projected_correction_bytes_thin_k{thin_k}']:,} B, response "
        f"{anchor[f'projected_response_bytes_thin_k{thin_k}_before_eq_reduction_overhead']:,} B "
        "before eq-reduction overhead; "
        f"clears 75,000,000 B: {anchor['clears_75_000_000_byte_desideratum']}."
    )
    print("Assumptions:")
    for assumption in report["assumptions"]:
        print(f"  - {assumption}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        choices=("all", "gpt-oss-20b", "llama-8b", "gpt2-c1-anchor"),
        default="all",
    )
    parser.add_argument("--prompt-tokens", type=int, default=DEFAULT_PROMPT_TOKENS)
    parser.add_argument("--decode-tokens", type=int, default=DEFAULT_DECODE_TOKENS)
    parser.add_argument("--thin-k", type=int, default=DEFAULT_THIN_K)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workload = Workload(args.prompt_tokens, args.decode_tokens)
    choices = {
        "gpt-oss-20b": gpt_oss_20b(),
        "llama-8b": llama_8b(),
        "gpt2-c1-anchor": gpt2_c1_anchor(),
    }
    configs = (
        [choices["gpt-oss-20b"], choices["llama-8b"]]
        if args.model == "all"
        else [choices[args.model]]
    )
    report = build_report(configs, workload, args.thin_k)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# Reproduce the frozen M1-M9 named-assumption audit used by the artifact.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if rg -n '\b(sorry|admit)\b' "$repo_root/lean" --glob '*.lean'; then
    echo "audit_lean: unresolved sorry/admit found" >&2
    exit 1
fi

output="$(cd "$repo_root/lean" && lake env lean Audit.lean 2>&1)"
printf '%s\n' "$output"

audited_theorems=(
    VoltaZk.bsc_zeroBatch_perfect_zk
    VoltaZk.blind_sumcheck_sound
    VoltaZk.authenticated_cache_sound
    VoltaZk.sub_zeroOpen_sound
    VoltaZk.sequential_composition_perfect_zk
    VoltaZk.prod_perfect_sim
    VoltaZk.prodBatch_sound
    VoltaZk.PCSOpening.opening_mac_sound
    VoltaZk.card_scalarRlc_zero_le
    VoltaZk.zeroBatch_sound_scalar
    VoltaZk.prodBatch_sound_scalar
    VoltaZk.blind_sumcheck_sound_scalar
    VoltaZk.kv_cache_sound_scalar
    VoltaZk.authenticated_cache_sound_scalar
    VoltaZk.outer_scalar_batch_blind_sumcheck_sound
    VoltaZk.scalar_batch_blind_sumcheck_sound
)

for theorem in "${audited_theorems[@]}"; do
    if ! rg -Fq "$theorem" <<<"$output"; then
        echo "audit_lean: missing named theorem in audit output: $theorem" >&2
        exit 1
    fi
done

expected='depends on axioms: \[propext, Classical.choice, Quot.sound\]'
count="$(rg -c "$expected" <<<"$output")"
expected_count="${#audited_theorems[@]}"
if [[ "$count" != "$expected_count" ]]; then
    echo "audit_lean: expected $expected_count audited theorems with only the standard Lean axioms; got $count" >&2
    exit 1
fi
if rg -q 'VoltaZk\.Ideal|FerretRealizesSVOLE|WeightPCSBinding|LogUpGKRSound|UCComposition' <<<"$output"; then
    echo "audit_lean: a deferred named assumption entered the proved M1-M9 boundary" >&2
    exit 1
fi

declared="$(rg -c '^axiom (FerretRealizesSVOLE|WeightPCSBinding|LogUpGKRSound|UCComposition) : Prop$' \
    "$repo_root/lean/VoltaZk/Ideal.lean")"
if [[ "$declared" != 4 ]]; then
    echo "audit_lean: VoltaZk.Ideal named-assumption inventory changed" >&2
    exit 1
fi

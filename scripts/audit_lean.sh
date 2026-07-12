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

expected='depends on axioms: \[propext, Classical.choice, Quot.sound\]'
count="$(printf '%s\n' "$output" | rg -c "$expected")"
if [[ "$count" != 8 ]]; then
    echo "audit_lean: expected 8 audited theorems with only the standard Lean axioms; got $count" >&2
    exit 1
fi
if printf '%s\n' "$output" | rg -q 'VoltaZk\.Ideal|FerretRealizesSVOLE|WeightPCSBinding|LogUpGKRSound|UCComposition'; then
    echo "audit_lean: a deferred named assumption entered the proved M1-M9 boundary" >&2
    exit 1
fi

declared="$(rg -c '^axiom (FerretRealizesSVOLE|WeightPCSBinding|LogUpGKRSound|UCComposition) : Prop$' \
    "$repo_root/lean/VoltaZk/Ideal.lean")"
if [[ "$declared" != 4 ]]; then
    echo "audit_lean: VoltaZk.Ideal named-assumption inventory changed" >&2
    exit 1
fi

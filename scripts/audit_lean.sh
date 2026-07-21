#!/usr/bin/env bash
# Reproduce the M1-M11 named-assumption audit used by the artifact.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
audit_file="$repo_root/lean/Audit.lean"
ideal_file="$repo_root/lean/VoltaZk/Ideal.lean"

if rg -n '\b(sorry|admit)\b' "$repo_root/lean" --glob '*.lean'; then
    echo "audit_lean: unresolved sorry/admit found" >&2
    exit 1
fi

# Lean may wrap a long `#print axioms` result across physical lines (the
# permanent beta-collision theorem is long enough to trigger this).  Join only
# continuation lines inside an open axiom list; all later validation still
# checks one result per requested theorem and every dependency by exact name.
raw_output="$(cd "$repo_root/lean" && lake env lean Audit.lean 2>&1)"
output="$(awk '
    pending != "" {
        pending = pending " " $0
        if ($0 ~ /]$/) {
            print pending
            pending = ""
        }
        next
    }
    /^\047[^\047]+\047 depends on axioms: \[[^]]*$/ && $0 !~ /]$/ {
        pending = $0
        next
    }
    { print }
    END {
        if (pending != "") {
            print pending
            exit 2
        }
    }
' <<<"$raw_output")"
printf '%s\n' "$output"

mapfile -t audited_theorems < <(
    sed -nE \
        's/^[[:space:]]*#print[[:space:]]+axioms[[:space:]]+([[:alnum:]_.]+)[[:space:]]*(--.*)?$/\1/p' \
        "$audit_file"
)
if [[ "${#audited_theorems[@]}" == 0 ]]; then
    echo "audit_lean: Audit.lean declares no theorem audits" >&2
    exit 1
fi

unique_count="$(printf '%s\n' "${audited_theorems[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "$unique_count" != "${#audited_theorems[@]}" ]]; then
    echo "audit_lean: duplicate #print axioms target in Audit.lean" >&2
    exit 1
fi

for theorem in "${audited_theorems[@]}"; do
    mapfile -t theorem_lines < <(rg -F "'$theorem' " <<<"$output")
    if [[ "${#theorem_lines[@]}" != 1 ]]; then
        echo "audit_lean: expected one audit result for $theorem; got ${#theorem_lines[@]}" >&2
        exit 1
    fi

    line="${theorem_lines[0]}"
    if [[ "$line" == "'$theorem' does not depend on any axioms" ]]; then
        continue
    fi
    if [[ ! "$line" =~ ^\'$theorem\'\ depends\ on\ axioms:\ \[(.*)\]$ ]]; then
        echo "audit_lean: malformed axiom report for $theorem: $line" >&2
        exit 1
    fi

    IFS=',' read -r -a dependencies <<<"${BASH_REMATCH[1]}"
    for dependency in "${dependencies[@]}"; do
        dependency="${dependency#"${dependency%%[![:space:]]*}"}"
        dependency="${dependency%"${dependency##*[![:space:]]}"}"
        case "$dependency" in
            propext|Classical.choice|Quot.sound) ;;
            *)
                echo "audit_lean: non-standard axiom for $theorem: $dependency" >&2
                exit 1
                ;;
        esac
    done
done

reported_count="$(rg -c "^'[^']+' (depends on axioms:|does not depend on any axioms)" <<<"$output")"
if [[ "$reported_count" != "${#audited_theorems[@]}" ]]; then
    echo "audit_lean: Audit.lean/output theorem-count mismatch: expected ${#audited_theorems[@]}, got $reported_count" >&2
    exit 1
fi
if rg -q 'sorryAx|VoltaZk\.Ideal|FerretRealizesSVOLE|WeightPCSBinding|LogUpGKRSound|UCComposition' <<<"$output"; then
    echo "audit_lean: a deferred named assumption entered the proved M1-M11 boundary" >&2
    exit 1
fi

mapfile -t declared_axioms < <(
    sed -nE 's/^[[:space:]]*axiom[[:space:]]+([[:alnum:]_]+)[[:space:]]*:.*$/\1/p' "$ideal_file"
)
expected_axioms=(FerretRealizesSVOLE WeightPCSBinding LogUpGKRSound UCComposition)
if [[ "${#declared_axioms[@]}" != "${#expected_axioms[@]}" ]]; then
    echo "audit_lean: VoltaZk.Ideal named-assumption inventory changed" >&2
    exit 1
fi
for expected_axiom in "${expected_axioms[@]}"; do
    if [[ " ${declared_axioms[*]} " != *" $expected_axiom "* ]] \
        || ! rg -q "^axiom $expected_axiom : Prop$" "$ideal_file"; then
        echo "audit_lean: VoltaZk.Ideal named-assumption inventory changed" >&2
        exit 1
    fi
done

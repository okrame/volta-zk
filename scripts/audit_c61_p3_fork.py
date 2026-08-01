#!/usr/bin/env python3
"""Fail-closed provenance audit for the feature-only C6.1 Plonky3 fork."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "rust" / "third_party"
MANIFEST = THIRD_PARTY / "C61_P3_UPSTREAM_SHA256SUMS"
REVISION = "66e290615de1858f2f2f6a804158064c406cda1c"

ALLOWED_DELTAS = frozenset(
    {
        "sumcheck/src/zk/data.rs",
        "sumcheck/src/zk/mod.rs",
        "sumcheck/src/zk/prover/residual.rs",
        "sumcheck/src/zk/verifier.rs",
        "whir/src/fiat_shamir/domain_separator.rs",
        "whir/src/fiat_shamir/pattern.rs",
        "whir/src/lib.rs",
        "whir/src/pcs/zk/base_case/mod.rs",
        "whir/src/pcs/zk/base_case/prover.rs",
        "whir/src/pcs/zk/base_case/verifier.rs",
        "whir/src/pcs/zk/mod.rs",
        "whir/src/pcs/zk/proof.rs",
        "whir/src/pcs/zk/prover/mod.rs",
        "whir/src/pcs/zk/verifier/mod.rs",
    }
)

CRATES = {
    "sumcheck": THIRD_PARTY / "p3-sumcheck-c61",
    "whir": THIRD_PARTY / "p3-whir-c61",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict[str, str]:
    records: dict[str, str] = {}
    for line_number, raw in enumerate(MANIFEST.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or len(fields[0]) != 64:
            raise SystemExit(f"malformed upstream hash at line {line_number}")
        sha256, relative = fields
        if relative in records:
            raise SystemExit(f"duplicate upstream path: {relative}")
        records[relative] = sha256
    return records


def vendored_path(relative: str) -> Path:
    crate, inner = relative.split("/", 1)
    try:
        return CRATES[crate] / inner
    except KeyError as error:
        raise SystemExit(f"unknown manifest crate: {crate}") from error


def actual_sources() -> set[str]:
    paths: set[str] = set()
    for crate, root in CRATES.items():
        for path in (root / "src").rglob("*.rs"):
            paths.add(f"{crate}/{path.relative_to(root).as_posix()}")
    return paths


def require_source_guards() -> None:
    proof = (CRATES["whir"] / "src/pcs/zk/proof.rs").read_text()
    prover = (CRATES["whir"] / "src/pcs/zk/prover/mod.rs").read_text()
    verifier = (CRATES["whir"] / "src/pcs/zk/verifier/mod.rs").read_text()
    residual = (CRATES["sumcheck"] / "src/zk/prover/residual.rs").read_text()
    if "pub evals:" in proof:
        raise SystemExit("claimless ZK proof regressed to a clear evaluation field")
    if prover.count("into_zk_sumcheck_claimless(") != 2:
        raise SystemExit("claimless prover must use exactly two claimless sumcheck batches")
    if "verify_affine_claim" not in verifier:
        raise SystemExit("claimless verifier no longer performs affine replay")
    if "aux_claim,\n            false," not in residual:
        raise SystemExit("sumcheck claimless entry point no longer disables clear binding")

    adapter = (ROOT / "rust/volta-pcs/src/c61_authenticated_whir_p3.rs").read_text()
    production_adapter = adapter.split("#[cfg(test)]", 1)[0]
    if production_adapter.count("C61InteractiveChallenger::new_claimless(") != 2:
        raise SystemExit("claimless provider/verifier must use the no-skip challenger mode")
    if production_adapter.count(".observe_public_point(") != 2:
        raise SystemExit("claimless provider/verifier must explicitly bind the opening point")
    if production_adapter.count(".ensure_public_statement_bound()") != 2:
        raise SystemExit("claimless provider/verifier must fail closed on incomplete statements")
    if production_adapter.count("challenger.finish(") != 2:
        raise SystemExit("claimless provider/verifier must finalize strict wire accounting")
    if "proof.evals" in production_adapter:
        raise SystemExit("claimless adapter regressed to a clear evaluation codec field")
    if 'C61_AUTHENTICATED_P3_MAGIC: [u8; 8] = *b"C6AWP1\\0\\0"' not in production_adapter:
        raise SystemExit("claimless adapter strict codec identity changed")
    if "decode_c61_authenticated_p3_artifact_inner" not in production_adapter:
        raise SystemExit("claimless verifier no longer consumes the strict codec")
    verifier_adapter = production_adapter.split("fn verify_diagnostic(", 1)[1].split(
        "/// Run one reference-only", 1
    )[0]
    if any(
        forbidden in verifier_adapter
        for forbidden in ("artifact.provider_", "artifact.point", "artifact.target_key")
    ):
        raise SystemExit("claimless verifier regained provider-local fixture metadata")


def build_report() -> dict[str, object]:
    expected = load_manifest()
    actual = actual_sources()
    expected_paths = set(expected)
    missing = sorted(expected_paths - actual)
    extra = sorted(actual - expected_paths)
    if missing or extra:
        raise SystemExit(f"fork source census mismatch: missing={missing}, extra={extra}")
    if len(expected) != 87:
        raise SystemExit(f"upstream source census changed: expected 87, got {len(expected)}")
    if len(ALLOWED_DELTAS) != 14:
        raise SystemExit("allowed C6.1 delta census must remain exactly 14 files")

    changed: list[str] = []
    for relative, upstream_hash in sorted(expected.items()):
        current_hash = digest(vendored_path(relative))
        if current_hash != upstream_hash:
            changed.append(relative)
            if relative not in ALLOWED_DELTAS:
                raise SystemExit(f"unregistered vendored source delta: {relative}")
    if set(changed) != ALLOWED_DELTAS:
        absent = sorted(ALLOWED_DELTAS - set(changed))
        raise SystemExit(f"registered C6.1 delta unexpectedly equals upstream: {absent}")

    for root in CRATES.values():
        if (root / "Cargo.lock").exists():
            raise SystemExit(f"generated library lockfile is forbidden: {root / 'Cargo.lock'}")
        if (root / "target").exists():
            raise SystemExit(f"crate-local Cargo target directory is forbidden: {root / 'target'}")
        cargo = (root / "Cargo.toml").read_text()
        upstream = (root / "UPSTREAM.md").read_text()
        if REVISION not in cargo or REVISION not in upstream:
            raise SystemExit(f"fork identity is not pinned in {root}")

    require_source_guards()
    return {
        "profile": "C6.1-p3-fork-provenance-v1",
        "upstream_revision": REVISION,
        "upstream_source_files": len(expected),
        "allowed_modified_source_files": changed,
        "allowed_modified_source_file_count": len(changed),
        "all_other_source_files_byte_identical": True,
        "generated_library_lockfiles_absent": True,
        "crate_local_target_directories_absent": True,
        "claimless_source_guards": True,
        "claimless_adapter_statement_guards": True,
        "claimless_strict_codec_guards": True,
        "verdict": "C61_PINNED_FORK_PROVENANCE_PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["verdict"])
        print(f"upstream revision: {report['upstream_revision']}")
        print(f"upstream source files: {report['upstream_source_files']}")
        print(f"registered source deltas: {report['allowed_modified_source_file_count']}")
        print("all other source files: byte-identical")


if __name__ == "__main__":
    main()

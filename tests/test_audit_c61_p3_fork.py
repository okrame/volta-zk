"""The provenance gate must reject edits even to registered source paths."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest


spec = importlib.util.spec_from_file_location(
    "fork_audit", Path(__file__).resolve().parents[1] / "scripts/audit_c61_p3_fork.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_reviewed_fork_and_mutations_fail_closed():
    report = audit.build_report()
    assert report["upstream_source_files"] == 96
    assert report["allowed_modified_source_file_count"] == 25
    assert report["reviewed_delta_content_pinned"] and not report["credit"]
    digest = audit.digest
    for relative, error in (
        ("sumcheck/src/strategy.rs", "reviewed vendored source content changed"),
        ("merkle-tree/src/merkle_tree.rs", "reviewed vendored source content changed"),
        ("merkle-tree/src/mmcs/pruned.rs", "unregistered vendored source delta"),
        ("whir/src/pcs/zk/constraint/mod.rs", "unregistered vendored source delta"),
    ):
        changed = audit.vendored_path(relative)
        assert changed.is_file()
        with patch.object(audit, "digest", side_effect=lambda p: "0" * 64 if p == changed else digest(p)):
            with pytest.raises(SystemExit, match=error):
                audit.build_report()
    actual = audit.actual_sources()
    for paths in (actual - {"sumcheck/src/strategy.rs"}, actual | {"whir/src/extra.rs"}):
        with patch.object(audit, "actual_sources", return_value=paths):
            with pytest.raises(SystemExit, match="fork source census mismatch"):
                audit.build_report()
    read_text = Path.read_text
    residual = audit.vendored_path("sumcheck/src/zk/prover/residual.rs")
    # The older method still contains `false`; test the actual generic wrapper.
    with patch.object(Path, "read_text", lambda p: read_text(p).replace(
            "aux_claim,\n        false,", "aux_claim,\n        true,") if p == residual else read_text(p)):
        with pytest.raises(SystemExit, match="no longer disables clear binding"):
            audit.require_source_guards()
    exists = Path.exists
    for root in audit.CRATES.values():
        for name, error in (("Cargo.lock", "library lockfile"), ("target", "target directory")):
            forbidden = root / name
            with patch.object(Path, "exists", lambda p: p == forbidden or exists(p)):
                with pytest.raises(SystemExit, match=error):
                    audit.build_report()

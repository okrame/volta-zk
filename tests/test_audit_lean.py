import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _audit_fixture(tmp_path: Path, audit_source: str) -> tuple[Path, dict[str, str]]:
    script_dir = tmp_path / "scripts"
    lean_dir = tmp_path / "lean"
    ideal_dir = lean_dir / "VoltaZk"
    fake_bin = tmp_path / "bin"
    script_dir.mkdir()
    ideal_dir.mkdir(parents=True)
    fake_bin.mkdir()

    script = script_dir / "audit_lean.sh"
    shutil.copy2(ROOT / "scripts" / "audit_lean.sh", script)
    script.chmod(0o755)
    (lean_dir / "Audit.lean").write_text(audit_source, encoding="utf-8")
    (ideal_dir / "Ideal.lean").write_text(
        "\n".join(
            [
                "axiom FerretRealizesSVOLE : Prop",
                "axiom WeightPCSBinding : Prop",
                "axiom LogUpGKRSound : Prop",
                "axiom UCComposition : Prop",
                "",
            ]
        ),
        encoding="utf-8",
    )

    fake_lake = fake_bin / "lake"
    fake_lake.write_text(
        """#!/usr/bin/env python3
from pathlib import Path

for source_line in Path("Audit.lean").read_text(encoding="utf-8").splitlines():
    fields = source_line.split()
    if len(fields) == 3 and fields[:2] == ["#print", "axioms"]:
        theorem = fields[2]
        if theorem.endswith("uses_forbidden"):
            print(f"'{theorem}' depends on axioms: [propext, Forbidden.axiom]")
        else:
            print(f"'{theorem}' depends on axioms: [propext]")
""",
        encoding="utf-8",
    )
    fake_lake.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    return script, env


def test_audit_derives_theorem_inventory_from_audit_lean(tmp_path: Path) -> None:
    script, env = _audit_fixture(
        tmp_path,
        "#print axioms VoltaZk.synthetic_first\n"
        "#print axioms VoltaZk.new_milestone_theorem\n",
    )

    result = subprocess.run([script], cwd=tmp_path, env=env, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert "VoltaZk.synthetic_first" in result.stdout
    assert "VoltaZk.new_milestone_theorem" in result.stdout


def test_audit_rejects_non_standard_axiom_for_derived_theorem(tmp_path: Path) -> None:
    script, env = _audit_fixture(
        tmp_path,
        "#print axioms VoltaZk.synthetic_first\n"
        "#print axioms VoltaZk.uses_forbidden\n",
    )

    result = subprocess.run([script], cwd=tmp_path, env=env, capture_output=True, text=True)

    assert result.returncode != 0
    assert "non-standard axiom" in result.stderr

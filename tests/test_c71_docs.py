"""Check the current handoff and preservation of relocated historical prose."""
import hashlib
import json
import os
from pathlib import Path
import re
import ast
import runpy
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / "docs/c7.1"
HISTORY = ROOT / "docs/c7.1-history"
LINK = re.compile(r"\[[^\]\n]*\]\(([^\s)]+)\)")
NOTICE = ("> Documento storico: descrive il proprio checkpoint, non le istruzioni correnti.\n"
          "> Per implementare usare il [design corrente](../c7.1/design.md); per la provenienza vedere la [mappa](README.md).\n\n")


def anchors(text):
    result = set(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', text))
    counts = {}
    fenced = False
    for line in text.splitlines():
        if line.startswith(("```", "~~~")):
            fenced = not fenced
        if fenced or not re.match(r"^#{1,6} ", line):
            continue
        heading = re.sub(r"^#{1,6} +| +#+$", "", line).lower()
        heading = re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")
        count = counts.get(heading, 0)
        counts[heading] = count + 1
        result.add(heading + (f"-{count}" if count else ""))
    return result


def test_current_handoff_structure_links_and_code_references():
    assert {p.name for p in CURRENT.iterdir()} == {
        "design.md", "specs.md", "security.md", "local-tests.md", "runpod-tests.md"}
    assert not list((ROOT / "docs").glob("c7.1-*.md"))
    assert not (ROOT / "docs/procedures/c71-calibration.md").exists()
    failures = []
    frozen = {"c7.1-gemma31b-design.md", "prototype-status-history-2026-09-07.md",
              "prototype-status-history-2026-09-10.md"}
    files = [*CURRENT.glob("*.md"),
             *(p for p in HISTORY.glob("*.md") if p.name not in frozen), ROOT / "AGENTS.md",
             ROOT / "README.md", ROOT / "docs/README.md"]
    for path in files:
        body = path.read_text()
        for target in LINK.findall(body):
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            dest = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not dest.exists():
                failures.append(f"{path.relative_to(ROOT)}: missing {target}")
            elif url.fragment and dest.suffix == ".md" and unquote(url.fragment) not in anchors(dest.read_text()):
                failures.append(f"{path.relative_to(ROOT)}: missing anchor {target}")
    assert not failures, "\n".join(failures)
    # Native filters in the runbook must still select a function in the source.
    rust = "\n".join(p.read_text() for folder in ("volta-pcs", "volta-pcg")
                     for p in (ROOT / "rust" / folder / "src").rglob("*.rs"))
    names = re.findall(r"fn\s+(\w+)\s*\(", rust)
    filters = re.findall(r"`((?:c71_|sourcewise_)[a-zA-Z0-9_]+)`", (CURRENT / "local-tests.md").read_text())
    assert all(any(name.startswith(f) for name in names) for f in filters), filters


def test_historical_content_and_frozen_snapshots_are_preserved():
    rows = re.findall(
        r"^\| `([^`]+)` \| \[[^\]]+\]\(([^)]+)\) \| ([^|]+) \| `([0-9a-f]{64})` \| `([0-9a-f]{64})` \|$",
        (HISTORY / "README.md").read_text(), re.M)
    assert len(rows) == 27
    for old, new, mode, exact, prose in rows:
        path = HISTORY / new
        body = path.read_bytes()
        if mode.strip() == "copia esatta":
            assert hashlib.sha256(body).hexdigest() == exact, old
        else:
            text = body.decode()
            assert text.startswith(NOTICE), new
            text = text.removeprefix(NOTICE)
            normalized = re.sub(r"(?<=\]\()([^\s)]+)(?=\))", "LINK", text)
            assert hashlib.sha256(normalized.encode()).hexdigest() == prose, old


def test_markdown_anchor_rules():
    assert anchors("# Unità e `byte`\n## Unità e byte\n<a id=\"manual\"></a>\n```\n# skip\n```\n") == {
        "unità-e-byte", "unità-e-byte-1", "manual"}


def test_runpod_command_snippets_parse_without_execution():
    body = (CURRENT / "runpod-tests.md").read_text()
    blocks = re.findall(r"```bash\n(.*?)\n```", body, re.S)
    assert len(blocks) >= 5
    for block in blocks:
        checked = subprocess.run(["bash", "-n"], input=block, text=True,
                                 capture_output=True, timeout=5)
        assert checked.returncode == 0, checked.stderr
        for python in re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", block, re.S):
            ast.parse(python)


def test_runpod_harness_rejects_exposed_local_env(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    harness = scripts / "runpod_harness.sh"
    harness.write_bytes((ROOT / "scripts/runpod_harness.sh").read_bytes())
    local_env = tmp_path / ".env"
    local_env.write_text("RUNPOD_API_KEY=fixture-not-a-secret\n")
    local_env.chmod(0o644)
    rejected = subprocess.run(["bash", str(harness), "local-secret-preflight"],
                              capture_output=True, text=True, timeout=5)
    assert rejected.returncode != 0 and "chmod 600" in rejected.stderr
    local_env.chmod(0o600)
    accepted = subprocess.run(["bash", str(harness), "local-secret-preflight"],
                              capture_output=True, text=True, timeout=5)
    assert accepted.returncode == 0, accepted.stderr


def test_documented_input_identities_match_ingest_and_workload():
    ingest = runpy.run_path(str(ROOT / "scripts/c7_d126_gemma_weight_ingest.py"))
    specs = (CURRENT / "specs.md").read_text()
    for name in ("MODEL", "REVISION", "METADATA_SHA256"):
        assert ingest[name] in specs
    for name, shard in ingest["SHARDS"].items():
        assert name in specs and shard["lfs_sha256"] in specs
        assert f'{shard["bytes"]:,}'.replace(",", ".") in specs
    workload = ROOT / "manifests/c7-d126-gemma31b-workload-v1.json"
    assert hashlib.sha256(workload.read_bytes()).hexdigest() in specs


def test_runpod_build_stops_on_each_cargo_failure(tmp_path):
    body = (CURRENT / "runpod-tests.md").read_text()
    build = re.search(r"run_step 1800 build bash -c '\n(.*?)\n'", body, re.S).group(1)
    (tmp_path / "rust").mkdir()
    # Replace compilers in this shell only: no build, downloads or provider calls.
    stubs = ('cargo() { if [[ "$1" == "$FAIL_AT" ]]; then return 17; fi; };\n'
             'rustc() { echo unexpected-later-command; };\n')
    for failure in ("fetch", "build"):
        run = subprocess.run(["bash", "-c", stubs + build], text=True,
                             capture_output=True, timeout=5,
                             env={**os.environ, "ROOT": str(tmp_path), "FAIL_AT": failure})
        assert run.returncode == 17, run.stderr
        assert "unexpected-later-command" not in run.stdout


def test_runpod_manifest_records_relative_paths_sizes_hashes_and_refuses_overwrite(tmp_path):
    body = (CURRENT / "runpod-tests.md").read_text()
    snippets = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", body, re.S)
    script, = [snippet for snippet in snippets if "manifest = root / 'files.json'" in snippet]
    (tmp_path / "logs").mkdir()
    (tmp_path / "weights").mkdir()
    payloads = {"candidate.json": b"{}\n", "logs/a space.stdout": b"ok\n"}
    for name, payload in payloads.items():
        (tmp_path / name).write_bytes(payload)
    (tmp_path / "weights/private.packed").write_bytes(b"exclude")
    command = [sys.executable, "-c", script]
    env = {**os.environ, "RUN": str(tmp_path)}
    run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr
    manifest = (tmp_path / "files.json").read_bytes()
    assert json.loads(manifest) == [
        {"path": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        for name, payload in sorted(payloads.items())]
    seal = (tmp_path / "files.json.sha256").read_bytes()
    assert seal.decode() == hashlib.sha256(manifest).hexdigest() + "  files.json\n"
    repeated = subprocess.run(command, env=env, capture_output=True, text=True, timeout=5)
    assert repeated.returncode != 0 and "new bundle required" in repeated.stderr
    assert (tmp_path / "files.json").read_bytes() == manifest
    assert (tmp_path / "files.json.sha256").read_bytes() == seal

"""Check the current handoff and preservation of relocated historical prose."""
import hashlib
from pathlib import Path
import re
import ast
import subprocess
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

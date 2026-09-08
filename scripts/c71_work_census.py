"""Native Goldilocks work from LLVM entry counters, without rewriting dependencies.

Base products INCLUDE products inside extensions; the extension columns are a
second view, never added to the base total. Squares count as one product in the
extension view. Delayed-reduction dot products count each bilinear base product.
"""

import hashlib
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REVISION = "66e290615de1858f2f2f6a804158064c406cda1c"


def command(*args):
    return subprocess.check_output([str(a) for a in args], text=True, cwd=ROOT / "rust")


def sources():
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    candidates = list((cargo_home / "git/checkouts").glob("plonky3-*/*/field/Cargo.toml"))
    upstreams = [p.parent.parent for p in candidates if
                 command("git", "-C", p.parent.parent, "rev-parse", "HEAD").strip() == REVISION]
    if len(upstreams) != 1:
        raise ValueError("ambiguous or missing pinned Plonky3 checkout")
    upstream = upstreams[0]
    crates = {"p3-field": upstream / "field", "p3-goldilocks": upstream / "goldilocks"}
    # Check all field implementation sources, including packed and helper paths.
    hashes = {}
    for crate in crates.values():
        for path in sorted((crate / "src").rglob("*.rs")):
            relative = path.relative_to(upstream).as_posix()
            original = subprocess.check_output(["git", "-C", str(upstream), "show", f"HEAD:{relative}"])
            if path.read_bytes() != original:
                raise ValueError(f"unreviewed native arithmetic: {relative}")
            hashes[relative] = hashlib.sha256(original).hexdigest()
    paths = [ROOT / "rust/volta-field/src/lib.rs",
             crates["p3-goldilocks"] / "src/goldilocks.rs",
             crates["p3-goldilocks"] / "src/aarch64_neon/packing.rs",
             crates["p3-field"] / "src/extension/cubic_extension.rs",
             crates["p3-field"] / "src/extension/packed_cubic_extension.rs"]
    hashes["volta-field/src/lib.rs"] = hashlib.sha256(paths[0].read_bytes()).hexdigest()
    cfg = command("rustc", "-C", "target-cpu=native", "--print", "cfg")
    if 'target_arch="aarch64"' not in cfg or 'target_feature="neon"' not in cfg or 'target_feature="sve2"' in cfg:
        raise ValueError("native census reviewed for aarch64 NEON without SVE2 only")
    return paths, hashes


def parse_lcov(text):
    """Retain concrete instantiations: equal demangled names can be distinct CGUs."""
    records = []
    for block in text.split("end_of_record"):
        filename, lines = None, {}
        for line in block.splitlines():
            if line.startswith("SF:"):
                filename = line[3:]
            elif line.startswith("FN:"):
                start, symbol = line[3:].split(",", 1)
                if symbol in lines:
                    raise ValueError("duplicate LLVM function mapping")
                lines[symbol] = int(start)
            elif line.startswith("FNDA:"):
                count, symbol = line[5:].split(",", 1)
                records.append({"source": filename, "line": lines[symbol],
                                "symbol": symbol, "calls": int(count)})
    return records


def rules(paths):
    # Source anchors select the implementation body, not forwarding MulAssign,
    # wrapper methods, closures, or a second copy of their descendants.
    anchors = [
        (0, "pub fn mul(self, rhs: Fp) -> Fp", "volta_fp", 1),
        (0, "pub fn mul(self, rhs: Fp2) -> Fp2", "volta_fp2", 1),
        (0, "pub fn mul_base(self, x: Fp) -> Fp2", "volta_fp2_base", 1),
        (0, "pub fn mul(self, rhs: Fp3) -> Fp3", "volta_fp3", 1),
        (0, "pub fn mul_base(self, rhs: Fp) -> Fp3", "volta_fp3_base", 1),
        (1, "fn mul(self, rhs: Self) -> Self", "p3_scalar_fp", 1),
        (1, "fn dot_product<const N: usize>", "p3_dot", None),
        (2, "fn mul(self, rhs: Self) -> Self", "p3_packed_fp", 2),
        (2, "fn square(&self) -> Self", "p3_packed_fp_square", 2),
        (3, "pub fn trinomial_cubic_mul<", "p3_fp3", None),
        (3, "pub fn cubic_square<", "p3_fp3_square", None),
        (3, "fn mul(self, rhs: A) -> Self", "p3_fp3_base", 1),
        (4, "fn mul(self, rhs: PF) -> Self", "p3_packed_fp3_base", 2),
    ]
    result = {}
    for file_index, anchor, category, scale in anchors:
        path = paths[file_index]
        matches = [i for i, line in enumerate(path.read_text().splitlines(), 1) if anchor in line]
        if len(matches) != 1:
            raise ValueError(f"arithmetic anchor changed: {anchor}")
        result[(str(path), matches[0])] = (category, scale)
    return result


def count_work(records, mapping, names):
    counts = dict.fromkeys(sorted({c for c, _ in mapping.values()}), 0)
    evidence = []
    for record in records:
        if record["calls"] == 0:
            continue
        rule = mapping.get((record["source"], record["line"]))
        if rule is None:
            continue
        category, scale = rule
        name = names[record["symbol"]]
        if category == "p3_dot":
            match = re.search(r"::dot_product::<(\d+)>$", name)
            if not match:
                raise ValueError(f"unrecognized dot product: {name}")
            size = int(match[1])
            # N=1 dispatches to scalar Mul, already counted; N=0 does no work.
            scale = size if size >= 2 else 0
        elif scale is None:
            if name.endswith("::<p3_goldilocks::goldilocks::Goldilocks>"):
                scale = 1
            elif name.endswith("::<p3_goldilocks::aarch64_neon::packing::PackedGoldilocksNeon>"):
                scale = 2
            else:
                raise ValueError(f"unrecognized cubic arithmetic: {name}")
        counts[category] += record["calls"] * scale
        evidence.append({**record, "name": name, "category": category, "products_per_call": scale})
    base = sum(counts[k] for k in ("volta_fp", "p3_scalar_fp", "p3_dot", "p3_packed_fp", "p3_packed_fp_square"))
    cubic = sum(counts[k] for k in ("volta_fp3", "p3_fp3", "p3_fp3_square"))
    return {"base_products_inclusive": base, "fp3_products_including_squares": cubic,
            "categories": counts, "native_entry_counters": evidence}


def validate_self_check(census):
    expected = {"volta_fp": 164, "volta_fp2": 1, "volta_fp2_base": 1,
                "volta_fp3": 1, "volta_fp3_base": 1, "p3_scalar_fp": 8,
                "p3_dot": 62, "p3_packed_fp": 8, "p3_packed_fp_square": 2,
                "p3_fp3": 3, "p3_fp3_square": 3, "p3_fp3_base": 1,
                "p3_packed_fp3_base": 2}
    phases = census["phases"]
    if (len(phases) != 2 or phases[0]["categories"] != expected
            or phases[0]["base_products_inclusive"] != 244
            or phases[0]["fp3_products_including_squares"] != 7
            or phases[1]["categories"] != dict.fromkeys(expected, 0) | {"volta_fp": 2048}
            or phases[1]["base_products_inclusive"] != 2048):
        raise ValueError("native scalar/packed/inverse/parallel counter fixture failed")


def validate_matrix_census(census, execution):
    phases = census["phases"]
    expected = ["initialization", "model_setup", "connection_pcg", "connection_lift"]
    attempt = ["integer_forward", "prover_reduction", "prover_commit_rematerialization",
               "prover_pcs", "encode", "decode", "verifier_reduction", "verifier_pcs"]
    if [p["name"] for p in phases] != expected + attempt + ["abort"] + attempt + ["finalization"]:
        raise ValueError("matrix phase coverage changed")
    for resource in execution["resources"]["phases"]:
        if (resource["heap_live_start_bytes"] + resource["heap_allocated_bytes"]
                - resource["heap_freed_bytes"] != resource["heap_live_end_bytes"]):
            raise ValueError("allocator census does not reconcile")
    for phase, item in zip((phases[5], phases[14]), (execution["attempts"][0], execution["attempts"][2])):
        if phase["categories"]["volta_fp3"] != item["matrix_reduction_only_fp3_products_prover"]:
            raise ValueError("prover reduction disagrees with source derivation")
    for phase, item in zip((phases[10], phases[19]), (execution["attempts"][0], execution["attempts"][2])):
        if phase["categories"]["volta_fp3"] != item["matrix_reduction_only_fp3_products_verifier"]:
            raise ValueError("verifier reduction disagrees with source derivation")
    for index in (1, 2, 6, 7, 11, 15, 16, 20):
        if phases[index]["base_products_inclusive"] <= 0:
            raise ValueError("native setup/PCS counters missing")


def collect(binary, directory, execution):
    paths, hashes = sources()
    mapping = rules(paths)
    phases = execution["resources"]["phases"]
    if len(list(directory.glob("phase-*.profraw"))) != len(phases):
        raise ValueError("phase snapshots do not reconcile")
    measured = []
    names = {}
    for phase in phases:
        raw = directory / f"phase-{phase['index']:02}.profraw"
        profile = directory / "phase.profdata"
        command("llvm-profdata-19", "merge", "-sparse", raw, "-o", profile)
        lcov = command("llvm-cov-19", "export", "-format=lcov", binary,
                       f"-instr-profile={profile}", *paths)
        records = parse_lcov(lcov)
        selected = [r for r in records if (r["source"], r["line"]) in mapping]
        missing = list(dict.fromkeys(r["symbol"] for r in selected if r["symbol"] not in names))
        if missing:
            decoded = subprocess.check_output(["llvm-cxxfilt-19"], input="\n".join(missing)+"\n", text=True).splitlines()
            if len(decoded) != len(missing):
                raise ValueError("LLVM demangler dropped symbols")
            names.update(zip(missing, decoded))
        measured.append({"index": phase["index"], "name": phase["name"],
                         **count_work(selected, mapping, names)})
    total = {key: sum(p[key] for p in measured) for key in
             ("base_products_inclusive", "fp3_products_including_squares")}
    return {"kind": "native LLVM atomic entry counters; diagnostic Goldilocks arithmetic",
            "credit": False, "phases": measured, "total": total,
            "upstream_revision": REVISION, "arithmetic_source_sha256": hashes,
            "base_product_semantics": "includes extension internals and delayed-reduction products; do not add Fp3 totals",
            "other_work": "AES, curve25519 OT, hashing, integer operations and allocation are included in phase time, not Goldilocks product counts",
            "timing_kind": "coverage instrumented; use the separate run without coverage for timing"}

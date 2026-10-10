"""Read-only verification of the retained C7.1 baseline; no provider or W execution."""
import csv
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
from datetime import datetime, timezone

root = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2]).resolve()
private = root / "artifact/c7.1-pod"
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root))

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def read(rel):
    return json.loads((root / rel).read_text())

checked = {}
failures = []
retired = {}
for receipt in private.glob("retention-*/plan.json"):
    for entry in json.loads(receipt.read_text()).get("retired", []):
        retired["artifact/c7.1-pod/" + entry["path"]] = {**entry, "receipt": str(receipt.relative_to(root))}

def verify(rel, expected_sha, expected_bytes=None):
    path = root / rel
    if not path.is_file():
        entry = retired.get(rel)
        status = "retired_with_receipt" if entry and entry["sha256"] == expected_sha and (expected_bytes is None or entry["bytes"] == expected_bytes) else "missing"
        result = {"path": rel, "status": status, "expected_sha256": expected_sha}
        if entry:
            result["receipt"] = entry["receipt"]
        if status == "missing":
            failures.append(result)
        return result
    if rel not in checked:
        checked[rel] = {"path": rel, "bytes": path.stat().st_size, "sha256": digest(path)}
    actual = checked[rel]
    good = actual["sha256"] == expected_sha and (expected_bytes is None or actual["bytes"] == expected_bytes)
    if not good:
        failures.append({**actual, "expected_sha256": expected_sha, "expected_bytes": expected_bytes})
    return {**actual, "status": "verified" if good else "mismatch"}

bundles = []
for manifest in sorted(private.glob("*/files.json")):
    sha_file = manifest.with_name("files.json.sha256")
    expected = sha_file.read_text().split()[0] if sha_file.exists() else digest(manifest)
    verified_manifest = verify(str(manifest.relative_to(root)), expected)
    entries = json.loads(manifest.read_text())
    results = [verify(str((manifest.parent / e["path"]).relative_to(root)), e["sha256"], e["bytes"]) for e in entries]
    actual_files = [p for p in manifest.parent.rglob("*") if p.is_file()]
    bundles.append({"path": str(manifest.parent.relative_to(root)), "manifest": verified_manifest,
                    "expected_files": len(entries), "verified_files": sum(e["status"] == "verified" for e in results),
                    "retired": [e for e in results if e["status"] == "retired_with_receipt"],
                    "actual_files_including_manifest": len(actual_files),
                    "actual_bytes_including_manifest": sum(p.stat().st_size for p in actual_files)})

close = "benchmarks/results/c71-h100-campaign-close-2026-10-10-304e0d74d5a9.json"
integrity = read("benchmarks/results/c71-h100-campaign-close-2026-10-10-304e0d74d5a9/final-integrity.json")
records = integrity["records"] + [{"path": close, "sha256": digest(root / close)}]
for rel in ["benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4.json", "benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json", "benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json"]:
    records.append({"path": rel, "sha256": digest(root / rel)})
public_records = []
public_artifacts = []
for record in records:
    public_records.append(verify(record["path"], record["sha256"], record.get("bytes")))
    for entry in read(record["path"]).get("artifacts", []):
        public_artifacts.append(verify(entry["path"], entry["sha256"], entry.get("bytes")))
for bundle in integrity["private_bundles"]:
    verify(bundle["path"] + "/files.json", bundle["manifest_sha256"])
gamma_evidence = [verify(e["path"], e["sha256"]) for e in integrity["gamma_evidence"]]
tables = verify("artifact/c7.1-pod/integer-timeout-20261007T140500Z/tables-fp64-full.bin", integrity["table_sha256"], 24414870)
selected_inputs = []
for path in sorted((private / "h100-components-20261009T194100Z/gamma-inputs").glob("*")):
    if path.is_file():
        selected_inputs.append(checked[str(path.relative_to(root))])
candidate = read("artifact/c7.1-pod/pilot-complete-20261007T133500Z/pilot-fp64-full/candidate.json")
ingest = read("artifact/c7.1-pod/preparation-20261007T114200Z/logs/ingest-canonical.stdout")
trace = read("artifact/c7.1-pod/integer-trace-20261007T155021Z/integer-1-attention-trace.json")
source_identity = [verify("manifests/c7-d126-gemma31b-source-metadata-v1.json", ingest["metadata_sha256"]),
                   verify("manifests/c7-d126-gemma31b-terminals-v1.csv", ingest["terminal_manifest_sha256"])]
all_files = [p for p in private.rglob("*") if p.is_file()]
binary_files = []
for path in all_files:
    with path.open("rb") as stream:
        prefix = stream.read(20)
    if prefix.startswith(b"\x7fELF"):
        machine = int.from_bytes(prefix[18:20], "little" if prefix[5] == 1 else "big")
        binary_files.append({**checked.get(str(path.relative_to(root)), {"path": str(path.relative_to(root)), "bytes": path.stat().st_size, "sha256": digest(path)}), "elf_machine": machine, "executed": False})

spikes = []
for stem, filename in [("c71-h100-canonical-06-2026-10-10-47af19bbe888", "canonical.memory.csv"), ("c71-h100-a-component04-2026-10-10-47af19bbe888", "commitment-a.memory.csv")]:
    rel = "benchmarks/results/" + stem + "/" + filename
    with (root / rel).open() as stream:
        rows = list(csv.DictReader(stream))
    a, b = rows[-2:]
    delta = {k: int(b[k]) - int(a[k]) for k in ["host_tree_rss_bytes", "host_tree_swap_bytes", "whole_gpu_used_bytes", "resident_host_W_lower_bound_bytes", "resident_device_W_bytes", "sampled_temporary_bytes"]}
    record = read("benchmarks/results/" + stem + ".json")
    spikes.append({"record": "benchmarks/results/" + stem + ".json", "samples_file": rel, "samples": len(rows),
                   "last_two_samples": [a, b], "last_delta": delta,
                   "last_native_progress": record["terminal"]["last_A_progress"],
                   "scope": "Sampled whole GPU/RSS and asynchronous boundary counters; allocation identity and CUDA event timing are absent; no causal attribution."})

prefill_observations = []
for stem in ["c71-h100-inference-01-2026-10-09-2a31625f849d", "c71-h100-prefill-2026-10-09-3e6c63a4250b"]:
    record = read("benchmarks/results/" + stem + ".json")
    prep = next(p for p in record["phase_intervals"] if p["phase"] == "preparation_including_inference")
    start = record["monitor"]["start_unix_seconds"] + prep["start_ns"] / 1e9
    end = record["monitor"]["start_unix_seconds"] + prep["end_ns"] / 1e9
    rel = "benchmarks/results/" + stem + "/cpu-gpu-observations.jsonl"
    samples = [json.loads(line) for line in (root / rel).read_text().splitlines()]
    # Runner elapsed and monitor UTC are not a shared CUDA clock. Discard
    # one observer period at both edges; retain the approximation explicitly.
    interior = [s for s in samples if start + 5 <= s["epoch"] <= end - 5]
    channels = {}
    for s in interior:
        for thread in s["threads"]:
            if thread["tid"] == s["pid"]:
                channel = thread["wait_channel"]
                channels[channel] = channels.get(channel, 0) + 1
    prefill_observations.append({"record": "benchmarks/results/" + stem + ".json", "samples_file": rel,
                                  "approximate_preparation_window_unix_seconds": [start, end],
                                  "edge_exclusion_seconds": 5, "interior_samples": len(interior),
                                  "main_thread_wait_channels": channels,
                                  "gpu_utilization_percent_samples": [int(s["gpu"]["utilization.gpu"]) for s in interior],
                                  "scope": "Five-second observer snapshots, approximate phase alignment, not time attribution or a causal profiler."})

report = {"schema": "c71-local-retained-baseline-inventory-v1", "date": "2026-10-10", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
          "source_git_sha": head, "git_dirty": dirty, "credit": False, "hardware_execution": False, "network_access": False,
          "host_machine": platform.machine(), "scope": "Read-only retained-file integrity and baseline reconstruction, not an inference/proof/performance run.",
          "private_actual_files": len(all_files), "private_actual_bytes": sum(p.stat().st_size for p in all_files),
          "private_largest_file_bytes": max(p.stat().st_size for p in all_files), "private_bundles": bundles,
          "verified_unique_files": len(checked), "public_records": public_records,
          "public_artifact_entries_checked": len(public_artifacts), "public_artifact_unique_files": len({e["path"] for e in public_artifacts}),
          "gamma_evidence": gamma_evidence, "tables": tables, "h100_selected_inputs": selected_inputs, "source_identity": source_identity,
          "gamma_weight_exponents": len(candidate["weight_exponents_by_tensor"]), "gamma_activation_exponents": len(candidate["activation_exponents_by_source"]),
          "gamma_weight_map_equals_ingest": candidate["weight_exponents_by_tensor"] == ingest["weight_exponents_by_tensor"],
          "retained_elf_files": binary_files, "retired_files": list(retired.values()),
          "not_retained": [{"kind": "packed_W", "bytes": ingest["packed_bytes"], "sha256": ingest["packed_sha256"], "body_present": False, "evidence": "retained ingest report only"},
                           {"kind": "original_safetensors", "bytes": ingest["source_bytes"], "sha256_by_shard": ingest["source_sha256"], "body_present": False},
                           {"kind": "complete_numeric_trace", "bytes": trace["trace_validation"]["bytes"], "sha256": trace["trace_validation"]["sha256"], "body_present": False, "evidence": "retained trace report and admission receipt only"}],
          "trace_report_top_level_independent_comparison_complete": trace["independent_comparison_complete"],
          "trace_report_selected_exact_comparison_complete": trace["trace_validation"]["exact_comparison_complete"],
          "trace_report_selected_independent_oracle_complete": trace["independent_oracle"]["complete"],
          "terminal_spikes": spikes, "prefill_observer_screen": prefill_observations, "failures": failures, "all_required_hashes_match": not failures}
with output.open("x") as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write("\n")
print(json.dumps({k: report[k] for k in ["source_git_sha", "git_dirty", "private_actual_files", "private_actual_bytes", "verified_unique_files", "public_artifact_entries_checked", "all_required_hashes_match"]}))
if failures:
    print(json.dumps(failures, indent=2))
    sys.exit(1)

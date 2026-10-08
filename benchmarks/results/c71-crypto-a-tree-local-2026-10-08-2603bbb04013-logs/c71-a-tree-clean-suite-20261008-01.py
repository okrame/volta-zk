import json, os, subprocess, sys
from pathlib import Path
ROOT=Path("/home/okrame/projects/volta-zk")
sha=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
assert sha=="2603bbb04013fa8909702164dd76ae74d79646ff"
check=lambda: not subprocess.check_output(["git","status","--porcelain"],cwd=ROOT,text=True)
assert check()
runner="/tmp/c71-local-check-20261008.py"
binary=str(ROOT/"rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1")
checks=[("build",0,["cargo","test","--offline","--locked","-j","1","-p","volta-pcs","--features","c71-seed6-reference","--lib","--no-run","--config","profile.dev.package.volta-pcs.opt-level=0"], ROOT/"rust")]
for label,fil in [
("a_tree","c71_b12_native_source_tree"),
("a_chain","c71_b12_native_source_composed_full_chain_original_mac_and_transcript"),
("a_coverage","c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows"),
("a_math","c71_b12_native_source_four_cosets_fft_hash_original_bytes"),
("a_failure","c71_b12_native_source_pending_coverage_owner_and_failure"),
("a_resource","c71_b12_native_source_geometry_and_resource_envelope"),
("salts","c71_b12_private_coins_"),
("w_tree","c71_b12_native_weight_tree"),
("w_chain","c71_b12_native_weight_composed_full_chain_original_mac_and_transcript"),
("w_resource","c71_b12_native_weight_geometry_and_resource_envelope"),
("producer","c71_canonical_device_replay_original_rows_windows_and_failure")]:
    checks.append((label,2048,[binary,fil,"--test-threads=1","--nocapture"],ROOT))
for label,fil in [("owner","tests/test_c71_range_native.py"),("tensor","tests/test_c71_pcs_tensor.py"),("docs","tests/test_c71_docs.py")]:
    checks.append((label,2048,[str(ROOT/".venv/bin/python"),"-m","pytest","-q","-s","-p","no:cacheprovider",fil],ROOT))
for label,limit,command,cwd in checks:
    assert check()
    base=f"/tmp/c71-a-tree-clean-{label}-20261008-01"
    result=subprocess.run([sys.executable,runner,base+".log",base+".json",str(limit),*command],cwd=cwd)
    assert check()
    report=Path(base+".json")
    data=json.loads(report.read_text())
    data.update(source_git_sha=sha,git_dirty=False)
    if result.returncode: raise SystemExit(result.returncode)
    print("PASS "+label,flush=True)

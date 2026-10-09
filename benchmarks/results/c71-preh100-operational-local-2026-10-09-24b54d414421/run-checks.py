import json, re, subprocess, sys
from pathlib import Path
root=Path('/home/okrame/projects/volta-zk')
out=Path('/tmp/c71-preh100-20261009-ops')
assert subprocess.check_output(['git','status','--porcelain'],cwd=root).strip()==b'', 'run of record requires clean tree'
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
(out/'source.json').write_text(json.dumps({'source_git_sha':source,'git_dirty':False})+'\n')
wrapper=root/'benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4/c71-local-check-20261008.py'
binary=root/'rust/target/debug/deps/volta_pcs-b3228fb890c6a4d7'
filters='''c71_b12_native_transform_natural_forward_inverse_and_work
c71_b12_native_private_salts_owner_exact_stream_hash_and_work
c71_b12_native_weight_tree_exact_roots_openings_and_work
c71_b12_native_source_tree_exact_roots_openings_histogram_and_work
c71_b12_native_query_exact_horner_windows_pads_and_resources
c71_b12_native_weight_query_horner_signed_pads_duplicates_and_accounting
c71_b12_native_query_composed_uncached_chain_original_mac_and_transcript
c71_b12_native_residual_paired_tree_root_salts_and_cpu_geometry
c71_b12_native_residual_query_horner_pads_duplicates_and_virtual_prefixes
c71_b12_native_residual_query_full_whir_a_wire_fs_rng_and_original_mac
c71_b12_native_residual_query_full_whir_w_wire_fs_rng_and_original_mac
c71_b12_native_residual_state_exact_coefficients_late_retention_and_views
c71_b12_native_linear_original_codecs_exact_coefficients_endpoints_and_work
c71_b12_native_linear_full_wire_fs_point_and_original_mac
c71_b12_sourcewise_linear_matches_dense_wire_fs_point_and_original_mac
c71_b12_native_hardware_parity_rejects_missing_and_host_library
c71_canonical_runner_
c71_canonical_packed_observer_precedes_load_and_preserves_codec
c71_progress_
c71_temporary_budget_combines_host_device_and_realloc_before_allocation
c71_b12_windowed_native_failure_before_authentication
c71_canonical_public_metadata_capacity_pinned_no_private_inputs
c71_canonical_public_metadata_telemetry_bounded_schema'''.splitlines()
commands=[(name,[str(binary),name,'--test-threads=1','--nocapture']) for name in filters]
commands += [('python-monitor',[str(root/'.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider','tests/test_c71_campaign_measure.py']),('python-docs',[str(root/'.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider','tests/test_c71_docs.py'])]
for index,(label,command) in enumerate(commands):
    stem=out/f'check-{index:02d}'
    result=subprocess.run([sys.executable,str(wrapper),str(stem.with_suffix('.log')),str(stem.with_suffix('.json')),'2048',*command],cwd=root,capture_output=True,text=True)
    print(json.dumps({'index':index,'filter':label,'returncode':result.returncode,'measurement':result.stdout.strip()}),flush=True)
    if result.returncode:
        print(stem.with_suffix('.log').read_text()[-10000:],flush=True)
        sys.exit(result.returncode)
    log=stem.with_suffix('.log').read_text()
    if index<len(filters):
        assert re.search(r'test result: ok\. [1-9][0-9]* passed;',log), 'zero-test result is not validation'
print('ALL_SCOPED_CHECKS_PASS',flush=True)

import pathlib,subprocess,sys
root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-b3228fb890c6a4d7'
filters=[
'c71_calibration_rms_program_screen_uses_original_compiler_and_rejects_bad_recipes',
'c71_canonical_resident_matrix_rne_original_owner_and_row_views',
'c71_canonical_resident_nonlinear_original_routes',
'c71_canonical_resident_rms_exact_u128_coefficients',
'c71_canonical_resident_pointwise_',
'c71_canonical_resident_embedding_',
'c71_canonical_resident_attention_o0',
'c71_canonical_resident_attention_o150',
'c71_canonical_resident_attention_o300',
'c71_canonical_device_replay_original_rows_windows_and_failure',
'c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows',
'c71_b12_native_source_tree_exact_roots_openings_histogram_and_work',
'c71_b12_native_source_composed_full_chain_original_mac_and_transcript',
'c71_b12_native_linear_full_wire_fs_point_and_original_mac',
'c71_b12_windowed_native_dense_chain',
]
failed=[]
for i,name in enumerate(filters):
 command=[sys.executable,str(pathlib.Path(__file__).parent/'run-check.py'),f'rust-{i:02}',str(binary),name,'--nocapture','--test-threads=1']
 r=subprocess.run(command,cwd=root)
 if r.returncode: failed.append(name)
print('FAILED_FILTERS',failed,flush=True)
sys.exit(bool(failed))

import hashlib, json, pathlib, subprocess
root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='3e7084e15bf824c540a9c53fe0f075378b438e3549f576d63e74b19fc510eb7b'
cases=[
('w-horner',['c71_b12_native_weight_query_horner_signed_pads_duplicates_and_accounting']),
('w-full',['c71_b12_native_residual_query_full_whir_w_wire_fs_rng_and_original_mac']),
('a-horner',['c71_b12_native_query_exact_horner_windows_pads_and_resources']),
('a-full',['c71_b12_native_residual_query_full_whir_a_wire_fs_rng_and_original_mac']),
('a-hash-lifetime',['c71_b12_native_source_four_cosets_fft_hash_original_bytes']),
('a-replay-lifetime',['c71_canonical_device_replay_original_rows_windows_and_failure']),
]
for label,filters in cases:
    prefix='/tmp/c71-initial-w-query-'+label+'-clean-20261009'
    result=subprocess.run(['python3','/tmp/c71-local-check-20261008.py',prefix+'.log',prefix+'.json','2048',str(binary),*filters,'--test-threads=1','--nocapture'],cwd=root)
    assert result.returncode==0,label
    assert '1 passed; 0 failed' in pathlib.Path(prefix+'.log').read_text(),label
prefix='/tmp/c71-initial-w-query-c-clean-20261009'
result=subprocess.run(['python3','/tmp/c71-local-check-20261008.py',prefix+'.log',prefix+'.json','2048',str(root/'.venv/bin/python'),'-m','pytest','-q','-s','-p','no:cacheprovider','tests/test_c71_pcs_query_weight.py','tests/test_c71_range_native.py'],cwd=root)
assert result.returncode==0
assert '2 passed' in pathlib.Path(prefix+'.log').read_text()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)
print(json.dumps({'source_sha':sha,'binary_sha256':'3e7084e15bf824c540a9c53fe0f075378b438e3549f576d63e74b19fc510eb7b','checks':7,'git_dirty':False}))

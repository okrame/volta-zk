import hashlib,pathlib,subprocess,json
root=pathlib.Path('/home/okrame/projects/volta-zk');binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='3e7084e15bf824c540a9c53fe0f075378b438e3549f576d63e74b19fc510eb7b'
for i,filter in enumerate([
 'c71_b12_query_factors_balanced_product_and_newton_match_direct_oracle',
 'c71_b12_query_small_remainders_exact_fp3_and_cost',
 'c71_b12_windowed_native_shared_resident_transcript_original_mac',
 'sourcewise_real_boolean_replay_matches_dense_coefficients_at_selected_depths',
 'c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals',
 'c71_b12_native_canonical_wire_body_geometry']):
 prefix=f'/tmp/c71-residual-local-{i+1:02}-clean-20261009'
 result=subprocess.run(['python3','/tmp/c71-local-check-20261008.py',prefix+'.log',prefix+'.json','2048',str(binary),filter,'--test-threads=1','--nocapture'],cwd=root)
 assert result.returncode==0,filter
 assert '1 passed; 0 failed' in pathlib.Path(prefix+'.log').read_text(),filter
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)
with pathlib.Path('/tmp/c71-residual-local-suite-attestation-20261009.json').open('x') as output:
 json.dump({'source_git_sha':sha,'git_dirty':False,'before_and_after_clean':True,'binary_sha256':'3e7084e15bf824c540a9c53fe0f075378b438e3549f576d63e74b19fc510eb7b','checks':6},output,indent=2)
print('6 finite residual checks PASS, source clean and unchanged')

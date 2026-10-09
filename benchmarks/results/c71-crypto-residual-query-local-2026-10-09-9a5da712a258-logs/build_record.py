#!/usr/bin/env python3
"""Assemble one immutable local S1/Query E record after root's clean checks.

Prepared only: does not run builds/tests or allocate any W/A witness.
Usage: python3 build_record.py --manifest FINAL.json --output-dir OUTPUT
FINAL uses the root clean-suite shape plus inputs_sha256 and binary_path:
  source_git_sha, git_dirty:false, binary_sha256, binary_path,
  inputs_sha256:{repo_relative_path:sha256}, checks:[per-check receipts].
Each final check must carry its own source_git_sha/git_dirty/binary_sha256.
Optional: artifacts:[path or {path,name}], preliminary_checks:[receipt or
{path,classification,source_git_sha,git_dirty,binary_sha256}], accounting,
readiness, remaining, review, prior_stage, build_description, platform/machine,
status, final_suite_report. An incomplete status retains failed clean checks.
Output defaults to /tmp; root explicitly selects benchmarks/results to publish.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess

DATE='2026-10-09'
ROOT=pathlib.Path('/home/okrame/projects/volta-zk')
SHA=re.compile(r'^[0-9a-f]{40}$')
DIGEST=re.compile(r'^[0-9a-f]{64}$')
MARKER=re.compile(r'(C71_[A-Z0-9_]+) (\{.*\})$')


def digest(path):
    value=hashlib.sha256()
    with pathlib.Path(path).open('rb') as source:
        for block in iter(lambda:source.read(1<<20),b''):value.update(block)
    return value.hexdigest()


def load(path):return json.loads(pathlib.Path(path).read_text())


def git(root,*args):return subprocess.check_output(['git',*args],cwd=root)


def metrics(log):
    result={}
    for line in pathlib.Path(log).read_text().splitlines():
        match=MARKER.search(line)
        if match:
            value=json.loads(match[2])
            assert value.get('credit',False) is False and value.get('gpu_execution',False) is False
            result.setdefault(match[1],[]).append(value)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',required=True,type=pathlib.Path)
    parser.add_argument('--repo-root',type=pathlib.Path,default=ROOT)
    parser.add_argument('--output-dir',type=pathlib.Path,default=pathlib.Path('/tmp/c71-residual-query-record-20261009/output'))
    args=parser.parse_args();root=args.repo_root.resolve();final=load(args.manifest)
    sha=final['source_git_sha'];assert SHA.fullmatch(sha) and final['git_dirty'] is False
    binary_sha=final['binary_sha256'];assert DIGEST.fullmatch(binary_sha)
    assert git(root,'rev-parse','HEAD').decode().strip()==sha
    assert not git(root,'status','--porcelain'), 'root must finish on a clean source tree before assembling evidence'
    binary=pathlib.Path(final.get('binary_path','rust/target/debug/deps/volta_pcs-efe6791186972026'))
    if not binary.is_absolute():binary=root/binary
    assert digest(binary)==binary_sha
    inputs=final['inputs_sha256'];assert inputs
    for path,expected in inputs.items():
        assert not pathlib.Path(path).is_absolute() and '..' not in pathlib.Path(path).parts
        assert DIGEST.fullmatch(expected)
        assert hashlib.sha256(git(root,'show',sha+':'+path)).hexdigest()==expected,(path,'source digest differs at recorded commit')
    status=final.get('status','PASS_LOCAL_RESIDENT_S1_QUERY_E_OWNER_CALLER_AND_REDUCED_FULL_WHIR_WIRE')
    assert status in ('PASS_LOCAL_RESIDENT_S1_QUERY_E_OWNER_CALLER_AND_REDUCED_FULL_WHIR_WIRE',
                      'PASS_LOCAL_S1_QUERY_E_REDUCED_WHIR_COMPOSED_D15_INCOMPLETE')
    originals=final['checks'];assert originals
    if status=='PASS_LOCAL_RESIDENT_S1_QUERY_E_OWNER_CALLER_AND_REDUCED_FULL_WHIR_WIRE':
        assert all(check['exit_code']==0 for check in originals),'full PASS status requires all final checks to pass'
    for check in originals:
        assert isinstance(check['exit_code'],int) and check['git_dirty'] is False
        assert check['source_git_sha']==sha and check['binary_sha256']==binary_sha
        assert pathlib.Path(check['log']).is_file()
    name='c71-crypto-residual-query-local-'+DATE+'-'+sha[:12]
    output=args.output_dir.resolve();record_path=output/(name+'.json');logs=output/(name+'-logs')
    assert not record_path.exists() and not logs.exists(),'immutable record/log directory already exists'
    output.mkdir(parents=True,exist_ok=True);logs.mkdir()
    artifact_manifest=[];saved={}
    def relative(path):
        try:return str(path.relative_to(root))
        except ValueError:return str(path)
    def save(path,label=None):
        path=pathlib.Path(path).resolve();assert path.is_file(),str(path)
        if path in saved:return saved[path]
        label=label or path.name;assert pathlib.Path(label).name==label and label not in ('.','..')
        target=logs/label
        if target.exists():
            if digest(target)==digest(path):saved[path]=relative(target);return saved[path]
            target=logs/(path.parent.name+'-'+label);assert not target.exists(),str(target)
        shutil.copyfile(path,target);target.chmod(0o600)
        location=relative(target);saved[path]=location
        artifact_manifest.append(dict(path=location,bytes=target.stat().st_size,sha256=digest(target)))
        return location
    checks=[];aggregate={}
    for original in originals:
        check=dict(original);oldlog=pathlib.Path(check['log']);check['log']=save(oldlog)
        receipt=oldlog.with_suffix('.json')
        if receipt.is_file():check['receipt']=save(receipt)
        check['record_run']=True;check.setdefault('kind','local')
        checks.append(check)
        check['metrics']=metrics(oldlog)
        if check['exit_code']==0:
            for marker,values in check['metrics'].items():aggregate.setdefault(marker,[]).extend(values)
    # Preserve each attempt's own provenance. Historical clean suites retain
    # their actual SHA/clean flag; dirty/unknown receipts are never promoted.
    preliminary=[];seen_receipts=set();overrides={}
    for spec in final.get('preliminary_checks',[]):
        spec={'path':str(spec)} if isinstance(spec,(str,pathlib.Path)) else dict(spec)
        overrides[pathlib.Path(spec['path']).resolve()]=spec
    def preserve(spec,classification):
        spec={'path':str(spec)} if isinstance(spec,(str,pathlib.Path)) else dict(spec)
        path=pathlib.Path(spec['path']).resolve()
        if path in seen_receipts:return
        spec.update(overrides.get(path,{}))
        seen_receipts.add(path);data=load(path);save(path)
        if 'checks' in data:
            source_sha=spec.get('source_git_sha',data.get('source_git_sha'));dirty=spec.get('git_dirty',data.get('git_dirty'));bs=spec.get('binary_sha256',data.get('binary_sha256'))
            for raw in data['checks']:
                check=dict(raw);check['record_run']=False;check['classification']=spec.get('classification',classification)
                check.setdefault('source_git_sha',source_sha);check.setdefault('git_dirty',dirty);check.setdefault('binary_sha256',bs)
                check['receipt_container']=saved[path]
                oldlog=pathlib.Path(check['log']);check['log']=save(oldlog);check['metrics']=metrics(oldlog);preliminary.append(check)
                leaf=pathlib.Path(raw['log']).with_suffix('.json')
                if leaf.is_file():save(leaf)
        elif 'log' in data:
            check=dict(data);check['record_run']=False;check['classification']=spec.get('classification',classification)
            for key in ('source_git_sha','git_dirty','binary_sha256'):check[key]=spec.get(key,check.get(key))
            oldlog=pathlib.Path(check['log']);check['log']=save(oldlog);check['receipt']=saved[path]
            check['metrics']=metrics(oldlog);preliminary.append(check)
        else:
            raise AssertionError('preliminary receipt lacks checks/log: '+str(path))
    historical=[('/tmp/c71-s1-query-clean-suite-20261009.json','historical_clean_suite_failed_W_fixture'),
                ('/tmp/c71-s1-query-clean-suite-02-20261009.json','historical_clean_suite_15_PASS_superseded_source'),
                ('/tmp/c71-source-frontier-metadata-pre01-20261009.json','metadata_screen_failed_new_frontier_bound'),
                ({'path':'/tmp/c71-s1-query-trusted-owner-pre01-20261009.json','git_dirty':True},'dirty_candidate_C_owner_4_PASS')]
    for path,classification in historical:preserve(path,classification)
    for pattern in ['c71-s1-query-build-pre*-20261009.json','c71-s1-query-owner-pre*-20261009.json',
                    'c71-residual-owner-pre*-20261009.json','c71-residual-math-pre*-20261009.json',
                    'c71-query-e-loader-pre*-20261009.json','c71-query-e-parallel-loader-pre*-20261009.json',
                    'c71-s1-query-ledger-legacy-pre*-20261009.json']:
        for path in sorted(pathlib.Path('/tmp').glob(pattern)):preserve(path,'preparation_receipt_not_run_of_record')
    for spec in final.get('preliminary_checks',[]):preserve(spec,'root_declared_preparation')
    preparation=[
        '/tmp/c71-s1-query-shadow-manifest-20261009.json',
        '/tmp/c71-residual-query-owner-20261009/combined-owner.patch',
        '/tmp/c71-query-e-rust-20261009/s1-query-e-rust.patch',
        '/tmp/c71-query-e-rust-20261009/manifest.json',
        '/tmp/c71-pcs-query-e-20261009/manifest.json',
        '/tmp/c71-s1-query-fixture-fix-20261009/dyadic-ragged-fixture.patch',
        '/tmp/c71-native-a-chain-fixture-20261009/fixture-seams.patch',
        '/tmp/c71-residual-frontier-revert-20261009/remove-redundant-frontier.patch',
        '/tmp/c71-source-frontier-metadata-20261009/check_frontier.py']
    for path in preparation:save(path)
    for pattern in ['c71-residual-owner-shadow*-source-20261009.json',
                    'c71-query-e-loader-shadow*-source-20261009.json',
                    'c71-query-e-parallel-loader-shadow*-source-20261009.json']:
        for path in sorted(pathlib.Path('/tmp').glob(pattern)):save(path)
    for spec in final.get('artifacts',[]):
        if isinstance(spec,str):save(spec)
        else:save(spec['path'],spec.get('name'))
    if final.get('final_suite_report'):save(final['final_suite_report'])
    save(args.manifest,'root-final-manifest.json');save(__file__)
    # Only successful checks on the final clean SHA feed headline metrics.
    # Named analytical subtotals must remain distinct from physical admission.
    accounting=dict(final.get('accounting',{}));assert accounting.get('joint_admitted',False) is False
    accounting.update(checks=len(checks),passed_checks=sum(c['exit_code']==0 for c in checks),
        failed_checks=sum(c['exit_code']!=0 for c in checks),serial=True,workers=1,joint_admitted=False,
        max_final_check_rss_bytes=max(c.get('max_rss_bytes',0) for c in checks),
        max_check_wall_s=max(c.get('wall_s',0) for c in checks),
        measured_installation_setup_inference_proof_verification=False,
        scope='Local host helper/deferred owner/Rust fixture checks and named public geometry; no complete physical memory admission')
    readiness=dict(final.get('readiness',{}));readiness.update(H100_campaign_authorized=False,H100_performance_measured=False,cuda_execution_verified=False)
    record=dict(schema='c71-crypto-preparation-local-v1',date=DATE,
        recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        status=status,
        credit=False,source_git_sha=sha,git_dirty=False,baseline='9033c64',goal_complete=False,goal_status='active',
        canonical_diagnostic='benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json',
        prior_stage=final.get('prior_stage','benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json'),
        readiness=readiness,
        provenance=dict(platform=final.get('platform',platform.platform()),machine=final.get('machine',platform.machine()),
            gpu_execution=False,cuda_compilation=False,inputs_sha256=inputs,
            gamma_identities_unchanged=True,
            native_fixture='Deferred fake CUDA driver plus shared host math and independent Rust/P3/Horner oracles; no CUDA kernel or scheduling execution',
            clean_suite='Every final check carries the final clean source SHA and binary digest; earlier clean checks retain their own SHA under preliminary_checks',
            build=final.get('build_description','Root serial builds/checks; actual commands and measured process resources retained in receipts'),
            preparation_scope='Source/patch manifests preserve preparation provenance; dirty or unrecorded source receipts have record_run:false and explicit unknown provenance fields'),
        binary=dict(path=relative(binary),bytes=binary.stat().st_size,sha256=binary_sha),
        checks=checks,metrics=aggregate,preliminary_checks=preliminary,
        failures_preserved=[
            dict(receipt='c71-s1-query-clean-suite-20261009.json',source_git_sha='03015da1b568970208503f088ed2ceb8c15cc9cf',git_dirty=False,
                reason='Full W fixture failed sealed mapping validation: non-dyadic tile; fixture corrected without weakening the owner guard'),
            dict(receipt='c71-source-frontier-metadata-pre01-20261009.json',exit_code=1,
                reason='New fixed 4096-interval frontier failed pinned metadata schedule, highwater52883 for old0/150/300; removed as redundant with original trusted canonical source-row coverage and dyadic byte partition',
                scope='Independent metadata replica; no W/A numerics, CUDA or protocol credit')]+
                [dict(name=c.get('name'),log=c['log'],receipt=c.get('receipt'),exit_code=c['exit_code'],
                      source_git_sha=c['source_git_sha'],git_dirty=False,binary_sha256=c['binary_sha256'],
                      reason='Final clean check failed or exceeded its frozen deadline; retained without complete composed-check credit')
                 for c in checks if c['exit_code']!=0],
        review=final.get('review',{}),
        invariants=dict(fields='PCS E v^3=v+1 distinct from original MAC Fp3 u^3=2; canonical LE limbs/bytes and signed biased codecs preserved',
            NoPeek='Numerical producer sees original buffers/layout only; PCS coins/EQ/pads and contraction covectors remain in consumers',
            source='Original trusted NativeSource contract preserved: canonical duplicate/omitted-row checks plus Bytes dyadic byte partition; standalone C spans/count do not establish uniqueness',
            lifecycle='Original opening/release before A late retention; immutable virtual views/read leases preserve promotion and retire; no full W retention',
            owner='Typed private planes seal group and limb ordinals; stale/foreign/pending handles and invalid spans/lineage fail closed; final flag/canonical checks and auxiliary frees precede publication',
            transcript='Reduced complete WHIR fixtures compare exact wire, FS/private RNG, roots/salts/pads and original ideal endpoint MAC; production AES PCG and one-time correlations unchanged',
            work='Analytical canonical A nonquery S1 passes35 and W paired coset groups64; all three query limbs load together, retained A queries need no producer replay; original W contractions/queries select only congruent indices across bands'),
        accounting=accounting,
        measurements_scope='Local host/model timings and named analytic work only; no H100 speedup, complete cryptographic phase latency or whole-pipeline physical memory claim',
        remaining=final.get('remaining',[
            'Initial W query remains CPU in this checkpoint; GKR/range/PCG and synchronization profile remains separate',
            'Complete joint resource accounting and physical runtime margin are not admitted by named subtotals',
            'sm_90 compilation and actual CUDA parity/performance require a newly authorized H100 campaign']),
        artifact_manifest=artifact_manifest,artifacts=len(artifact_manifest))
    with record_path.open('x') as output_file:json.dump(record,output_file,indent=2);output_file.write('\n')
    record_path.chmod(0o600)
    print(json.dumps(dict(record=relative(record_path),sha256=digest(record_path),source_git_sha=sha,
        artifacts=len(artifact_manifest),artifact_bytes=sum(a['bytes'] for a in artifact_manifest),
        checks=len(checks),credit=False,gpu_execution=False,joint_admitted=False)))


if __name__=='__main__':main()

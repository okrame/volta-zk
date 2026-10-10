import hashlib,json,pathlib,resource,subprocess,sys
resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
root=pathlib.Path('/home/okrame/projects/volta-zk')
archive=root/'benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9'
summary=json.loads((archive/'c71-gamma-screen-20261010-102ecf02.json').read_text())
manifest=json.loads((archive/'gamma/manifest.json').read_text())
sha=lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(archive/'gamma/manifest.json')==summary['input_manifest_sha256']
blueprints={}
for batch in manifest['batches']:
 inp=archive/'gamma'/batch['input']; out=archive/'gamma'/batch['output']
 assert sha(inp)==batch['sha256'] and sha(out)==summary['program_outputs_sha256'][batch['output']]
 expected=json.loads(inp.read_text()); actual=json.loads(out.read_text())
 assert actual['credit'] is False and len(expected)==len(actual['programs'])
 for a,e in zip(actual['programs'],expected):
  key=lambda v:(v['columns'],*v['exponents'],v['weighted'])
  assert key(a)==key(e) and key(a) not in blueprints
  assert a['depth']==len(a['layers']) and a['layers'][-1]['width']==1
  assert all(l['width']==l['and']+l['xor']+l['copy'] for l in a['layers'])
  blueprints[key(a)]=a
assert len(blueprints)==398
bundle=root/manifest['bundle']
oracle_pin=next(p for p in manifest['retained_inputs'] if p['path']=='oracle-plan-original.json')
oracle_path=bundle/oracle_pin['path']
assert oracle_path.stat().st_size==oracle_pin['bytes'] and sha(oracle_path)==oracle_pin['sha256']
oracle=json.loads(oracle_path.read_text())['contexts'][0]
assert oracle['old_tokens']==0
weights={w['id']:w['name'] for w in oracle['weights']}
sources={s['id']:s for s in oracle['sources']}
causal_norms=[s for s in oracle['steps'] if s['kind']=='norm']
def norm_ordinal(norm):
 statistic=sources[norm['outputs'][-2]]
 assert statistic['name'].startswith('S/') and statistic['codec_bytes']==6
 return int(statistic['name'][2:])
# Canonical::causal_order is the executor schedule. Sources::prepare uses
# rms.norms instead; Plan::rms_sources names their statistics S/0, S/1, ... .
norms=sorted(causal_norms,key=norm_ordinal)
assert len(norms)==421
assert [norm_ordinal(n) for n in norms]==list(range(421))
canonical_json=lambda value:json.dumps(value,separators=(',',':')).encode()
norm_order=[n['outputs'][-2] for n in norms]
causal_order=[norm_ordinal(n) for n in causal_norms]
np2=lambda n:1<<(n-1).bit_length() if n else 0
# Pinned 64-bit layouts: Gate24, ReplayPlan(two Vec)48, counts24,
# Vec24, usize/u64=8, ((Op,usize,usize),usize)=32; Circuit112.
GATE=24;WORD=8;PLAN_HEADER=72;CIRCUIT=112
rows={}
for name in ('admitted','rms-even-coarser','rms-even-finer'):
 entry=manifest['candidates'][name];path=archive/'gamma'/entry['path'];assert sha(path)==entry['sha256']
 candidate=json.loads(path.read_text());a=candidate['activation_exponents_by_source'];w=candidate['weight_exponents_by_tensor']
 keys=[]
 for n in norms:
  par=n['parameters'];weighted=par['weight'] is not None
  k=(par['columns'],a[str(n['inputs'][0])],w[weights[par['weight']]] if weighted else 0,a[str(n['outputs'][-1])],weighted)
  if k not in keys:keys.append(k)
 count=len(keys);original=summary['candidates'][name];assert count==original['programs']
 program_owned=original['compiled_program_owned_bytes']
 program_inner=program_owned-count*CIRCUIT
 outer_upper=(2*count+4)*CIRCUIT
 perdepth=[]
 for requested in range(original['depth']):
  per=[]
  for k in keys:
   p=blueprints[k];selected=min(requested,p['depth']);levels=p['layers'][:selected]
   nodes=sum(l['and']+l['xor'] for l in levels)
   output=levels[-1]['width'] if levels else p['ports']
   widest=max([p['ports']]+[l['width'] for l in levels])
   buckets=np2(max(4,(8*nodes+6)//7)) if nodes else 0
   hash_upper=buckets*33+32
   node_vec_upper=(2*nodes+4)*GATE
   output_vec_upper=(2*output+4)*WORD
   builder=3*hash_upper+4*node_vec_upper+(p['ports']+nodes)*9+(4*widest+4)*WORD
   per.append(dict(nodes=nodes,output=output,ports=p['ports'],builder=builder,plan=node_vec_upper+output_vec_upper))
  width=np2(max(p['output'] for p in per));assert width==original['joint_widths'][requested]
  previous=0;build=0
  for p in per:
   build=max(build,previous+p['builder']);previous+=p['plan']
  plan=count*PLAN_HEADER+previous
  initial_scratch=(count+width)*WORD
  build=max(build+count*PLAN_HEADER,plan+initial_scratch)
  input_cap=2*max(p['ports'] for p in per)+4
  values_cap=max(p['ports']+p['nodes'] for p in per)
  selected_cap=2*max(p['output'] for p in per)+4
  scratch=(count+width+input_cap+values_cap+selected_cap)*WORD
  moving=2*scratch
  packed=max(build,plan+moving)
  perdepth.append(dict(selected_replay_depth=requested,prover_gate_depth=requested+1,
   plan_heap_capacity_upper_bytes=plan,plan_build_heap_capacity_upper_bytes=build,
   scratch_retained_capacity_upper_bytes=scratch,scratch_moving_capacity_upper_bytes=moving,
   packed_additional_heap_upper_bytes=packed,
   packed_plus_original_programs_and_PYS_partial_upper_bytes=packed+program_inner+outer_upper+summary['invariants']['RMS_checkpoint_PYS_bytes']))
 maxima={key:max(perdepth,key=lambda d:d[key]) for key in ('plan_heap_capacity_upper_bytes','plan_build_heap_capacity_upper_bytes','scratch_retained_capacity_upper_bytes','packed_additional_heap_upper_bytes','packed_plus_original_programs_and_PYS_partial_upper_bytes')}
 rows[name]=dict(programs=count,compiled_program_owned_bytes_measured=program_owned,
  caller_program_keys_sha256=hashlib.sha256(canonical_json(keys)).hexdigest(),
  caller_program_keys=keys,
  whole_program_non_copy_gates=sum(sum(l['and']+l['xor'] for l in blueprints[k]['layers']) for k in keys),
  max_program_non_copy_gates=max(sum(l['and']+l['xor'] for l in blueprints[k]['layers']) for k in keys),
  max_original_layer_width=max(l['width'] for k in keys for l in blueprints[k]['layers']),
  caller_program_inner_capacity_bytes_measured=program_inner,caller_program_outer_vec_upper_bytes=outer_upper,
  original_PYS_checkpoint_bytes_unchanged=summary['invariants']['RMS_checkpoint_PYS_bytes'],
  maxima=maxima,per_depth=perdepth)
sourcefiles=[root/'scripts/c71_temporary_ledger.py',root/'rust/volta-pcs/src/c71_matrix/rms.rs',root/'rust/volta-pcs/src/c71_matrix/rms/gkr/patterns.rs',root/'rust/volta-pcs/src/c71_matrix/rms/gkr.rs',root/'rust/volta-pcs/src/c71_matrix/gemma/rms/caller.rs']
result=dict(schema='volta-c71-packed-replay-analytic-upper-v1',credit=False,complete_work=False,complete_physical_peak=False,gpu_execution=False,
 retained_metadata_source_sha=summary['source_git_sha'],input_manifest_sha256=summary['input_manifest_sha256'],
 oracle_plan_sha256=oracle_pin['sha256'],oracle_plan_bytes=oracle_pin['bytes'],
 norm_order_source='Plan::rms_sources assigns S/ordinal in rms.norms order; Sources::prepare deduplicates first occurrence of that order, independently of Canonical::causal_order.',
 caller_norm_statistic_source_ids_sha256=hashlib.sha256(canonical_json(norm_order)).hexdigest(),
 caller_norm_statistic_source_ids_first_eight=norm_order[:8],
 oracle_causal_norm_ordinals_first_eight=causal_order[:8],
 oracle_causal_norm_order_matches_caller=causal_order==list(range(421)),
 analysis_source_git_sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
 analysis_git_dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)),
 source_sha256={str(p.relative_to(root)):sha(p) for p in sourcefiles},
 allocation_scope='Upper requested heap capacity from original gate counts, not exact DAG capacity or observed RSS; pinned64-bit Rust Vec growth <=2N+4. No candidate admission.',
 named_concurrent_stack_array_bytes=64*12+64*(8+16),
 stack_scope='Source logical frame/cell arrays only; excludes adapter descriptors, compiler stack, machine frame and thread stacks; no physical stack bound.',
 caller_lifetime='Compiled circuits, profile mapping, statistics proofs/pending/triples and compactPYS remain during jointGKR. Packed plans/scratch created once per depth and dropped before indexedges; no coexistence with byteLUT. PCG/FS/W/setup/otherretainedstate external.',
 excluded='Other retained profiles/statistic proofs/pending/triples/correlationPCG/transcript/serialization, allocator, original RMS compiler Builder, complete host/device two-role lifetime, CUDA and hardware peak',candidates=rows)
result['legacy_fixed_package_upper_bytes']=3680
result['legacy_fixed_source']='scripts/c71_temporary_ledger.py complete_prepared_phases: replay_fixed=768+1032+1536+312+32'
result['comparison_scope']='Differences between conservative upper bounds, not measured memory savings. Candidate bounds grant no complete composed budget or admission.'
for row in rows.values():
 for depth in row['per_depth']:
  depth['packed_package_upper_with_legacy_fixed_bytes']=depth['packed_additional_heap_upper_bytes']+3680
  depth['packed_plus_original_programs_and_PYS_partial_with_legacy_fixed_upper_bytes']=depth['packed_plus_original_programs_and_PYS_partial_upper_bytes']+3680
 for key in ('packed_package_upper_with_legacy_fixed_bytes','packed_plus_original_programs_and_PYS_partial_with_legacy_fixed_upper_bytes'):
  row['maxima'][key]=max(row['per_depth'],key=lambda d:d[key])
assert len(sys.argv)<=2,'usage: python3 DRIVER [NEW_OUTPUT_JSON]'
out=pathlib.Path(sys.argv[1]) if len(sys.argv)==2 else pathlib.Path('/tmp/c71-gamma-packed-upper-20261010-02.json')
with out.open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
print('report',out,'sha256',sha(out))
for name,row in rows.items():
 print(name,row['programs'],{k:(v['selected_replay_depth'],v[k]) for k,v in row['maxima'].items()})

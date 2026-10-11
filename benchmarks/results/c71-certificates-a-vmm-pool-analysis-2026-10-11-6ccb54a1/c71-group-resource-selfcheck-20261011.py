import csv,importlib.util,json,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('report','/tmp/c71-group-resource-report-20261011.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'logs').mkdir()
 progress=[{'event':{'kind':'clock_anchor','clock':'CLOCK_MONOTONIC','instant_origin_lower_ns':100,'instant_origin_upper_ns':110}},
  {'elapsed_ns':20,'event':{'phase':'pcs_a_resident','work':{'boundary':'start','completed_groups':0}}},
  {'elapsed_ns':80,'event':{'phase':'pcs_a_resident','work':{'boundary':'end','completed_groups':1}}},
  {'elapsed_ns':90,'event':{'phase':'pcs_a_resident','work':{'boundary':'start','completed_groups':1}}}]
 (p/'journals.progress.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in progress))
 keys=['W_transition_incomplete','sampled_temporary_bytes','smaps_read_failures','monotonic_sample_start_ns','monotonic_sample_end_ns']
 def samples(rows):
  with (p/'logs/a.memory.csv').open('w') as f:
   w=csv.writer(f);w.writerow(keys);w.writerows(rows)
 samples([[0,999,0,129,140],[0,10,0,130,180],[0,999,0,150,181],[0,20,0,140,170],[1,999,0,140,170],[0,'',0,140,170],[0,999,0,200,210]])
 r=m.summarize(p)
 assert r['completed_groups']==1 and r['partial_groups']==[1]
 assert r['clock_anchor_uncertainty_ns']==10
 assert r['groups'][0]['contained_samples']==2 and r['groups'][0]['sampled_peak_bytes']==20
 assert r['samples_outside_completed_group_interiors']==3
 samples([[0,10,1,130,180]])
 try:m.summarize(p)
 except AssertionError as e:assert 'recovered smaps' in str(e)
 else:raise AssertionError('recovered read accepted as stable evidence')
 samples([[0,10,0,150,140]])
 try:m.summarize(p)
 except AssertionError:pass
 else:raise AssertionError('inverted sample bracket accepted')
 samples([[0,10,0,130,180]])
 for altered in ([progress[0],progress[1],dict(progress[2],elapsed_ns=10)],
                 [progress[0],dict(progress[1],event={'phase':'pcs_a_resident','work':{'boundary':'start','completed_groups':1}}),dict(progress[2],event={'phase':'pcs_a_resident','work':{'boundary':'end','completed_groups':2}})]):
  (p/'journals.progress.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in altered))
  try:m.summarize(p)
  except AssertionError:pass
  else:raise AssertionError('invalid group prefix accepted')
print('PASS: clock uncertainty, straddling intervals, incomplete samples, partial groups, recovered smaps, inverted group and noncontiguous prefix rejection')

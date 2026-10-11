"""Summarize completed A groups from immutable, clock-bracketed evidence."""
import bisect,csv,hashlib,json,statistics,sys
from pathlib import Path


def summarize(root):
    progress=[json.loads(line) for line in (root/'journals.progress.jsonl').read_text().splitlines()]
    anchor=progress[0]['event'];assert anchor['kind']=='clock_anchor' and anchor['clock']=='CLOCK_MONOTONIC'
    lower,upper=anchor['instant_origin_lower_ns'],anchor['instant_origin_upper_ns'];assert lower<=upper
    groups={}
    for item in progress:
        event=item['event'];work=event.get('work',{})
        if event.get('phase')!='pcs_a_resident' or work.get('boundary') not in ('start','end'):continue
        boundary=work['boundary'];g=work['completed_groups']-(boundary=='end')
        entry=groups.setdefault(g,{'group':g,'sampled_peak_bytes':None,'contained_samples':0})
        assert boundary not in entry
        entry[boundary]=item['elapsed_ns']
    complete=[r for _,r in sorted(groups.items()) if 'start' in r and 'end' in r]
    assert [r['group'] for r in complete]==list(range(len(complete))), 'noncontiguous completed prefix'
    assert all(0<=r['start']<=r['end'] for r in complete), 'inverted group bracket'
    assert all(a['end']<=b['start'] for a,b in zip(complete,complete[1:])), 'overlapping group brackets'
    starts=[upper+r['start'] for r in complete]
    excluded=0
    for sample in csv.DictReader((root/'logs/a.memory.csv').open()):
        if sample['W_transition_incomplete']!='0' or not sample['sampled_temporary_bytes']:continue
        assert int(sample['smaps_read_failures'])==0,'recovered smaps samples require separate treatment'
        a,b=int(sample['monotonic_sample_start_ns']),int(sample['monotonic_sample_end_ns']);assert a<=b
        index=bisect.bisect_right(starts,a)-1
        if index<0 or b>lower+complete[index]['end']:
            excluded+=1;continue
        group=complete[index];group['contained_samples']+=1
        group['sampled_peak_bytes']=max(group['sampled_peak_bytes'] or 0,int(sample['sampled_temporary_bytes']))
    times=[(r['end']-r['start'])/1e9 for r in complete]
    assert all(r['contained_samples']>0 for r in complete)
    return {'credit':False,'physical_complete_peak':False,'input_directory':str(root),
            'clock_anchor_uncertainty_ns':upper-lower,'completed_groups':len(complete),
            'partial_groups':[g for g,r in groups.items() if 'end' not in r],
            'samples_outside_completed_group_interiors':excluded,
            'group_wall_seconds':None if not times else {'min':min(times),'median':statistics.median(times),'max':max(times),'sum':sum(times)},
            'groups':complete,
            'scope':'Only complete monitor collection intervals strictly contained in completed A group clock brackets; sampled peaks are not instantaneous or complete physical maxima.'}

if __name__=='__main__':
    assert len(sys.argv)==3
    root=Path(sys.argv[1]);result=summarize(root)
    result['input_files']=[{'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                          for p in [root/'journals.progress.jsonl',root/'logs/a.memory.csv']]
    with Path(sys.argv[2]).open('x') as output:json.dump(result,output,indent=2);output.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('groups','input_files')}))

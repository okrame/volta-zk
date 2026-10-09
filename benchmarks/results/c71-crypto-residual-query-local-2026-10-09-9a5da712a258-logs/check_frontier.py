#!/usr/bin/env python3
"""Public metadata replica of canonical A scan; never loads values/W/PCG/coins.

Authority paths: gemma.rs::compile/tiles; gemma/caller.rs::auxiliary_layout;
bytes.rs::new/resident_tile_fields; rms/gelu/gate_up/rope/attention/residual/
output/softmax source constructors; native/canonical.rs::ports/causal_order;
canonical_device.rs::batches/scan_inner; canonical_resident.rs output order.
The source census/live checks are independent existing Rust metadata constants.
This measures public interval scheduling only; not CUDA/protocol/H100 credit.
"""
from pathlib import Path
import argparse, bisect, hashlib, json
from collections import deque


def intervals(length):
    first = 0
    while length:
        size = 1 << (length.bit_length() - 1)
        yield first, size
        first += size
        length -= size


def build(root, old):
    manifest = json.loads((root/'manifests/c7-d126-gemma31b-qspec-dag-v1.json').read_text())
    raw = json.loads((root/'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_text())
    weights = {x['name']:x['shape'] for x in raw['tensors'] if x['disposition']=='private_text'}
    assert len(weights)==772
    assert manifest['model_config']['layers']==60
    cohorts=[]
    def cohort(layer,op,name,producer,decision=False):
        shape=weights[name]
        kind='lookup' if op=='embedding_lookup' else 'norm' if len(shape)==1 else 'matrix'
        width=shape[-1]; heads=1
        if op in ('q_norm','k_norm'):
            p='q' if op=='q_norm' else 'k'
            heads=weights[f'model.language_model.layers.{layer}.self_attn.{p}_proj.weight'][0]//width
        rows=(149 if op=='final_rms' else 50 if op=='lm_head' else 150)*heads
        columns=shape[0] if kind=='matrix' else width
        cohorts.append(dict(layer=layer,op=op,kind=kind,heads=heads,rows=rows,columns=columns,inner=width if kind=='matrix' else 0,producer=producer))
    cohort(None,'embedding_lookup','model.language_model.embed_tokens.weight',(None,'token_input'))
    norm_suffix={'input_rms':'input_layernorm.weight','q_norm':'self_attn.q_norm.weight','k_norm':'self_attn.k_norm.weight','post_attention_rms':'post_attention_layernorm.weight','pre_ffw_rms':'pre_feedforward_layernorm.weight','post_ffw_rms':'post_feedforward_layernorm.weight'}
    producers={'q_proj':'input_rms','q_norm':'q_proj','k_proj':'input_rms','k_norm':'k_proj','v_source':'input_rms','o_proj':'pv_matmul','post_attention_rms':'o_proj','pre_ffw_rms':'attention_residual_add','gate_proj':'pre_ffw_rms','up_proj':'pre_ffw_rms','down_proj':'gate_up_mul','post_ffw_rms':'down_proj'}
    for layer in range(60):
        for op,_,_,kind,_ in manifest['compact_program']['layer']:
            if kind=='none' or (op=='v_source' and layer%6==5):continue
            if op=='input_rms':producer=(None,'embedding_scale') if layer==0 else (layer-1,'layer_scalar_mul')
            else:producer=(layer,producers[op])
            suffix=norm_suffix.get(op)
            if suffix is None:
                role='v_proj' if op=='v_source' else op
                suffix=('self_attn.' if op in ('q_proj','k_proj','v_source','o_proj') else 'mlp.')+role+'.weight'
            cohort(layer,op,f'model.language_model.layers.{layer}.{suffix}',producer)
    cohort(None,'final_rms','model.language_model.norm.weight',(59,'layer_scalar_mul'))
    cohort(None,'lm_head','model.language_model.embed_tokens.weight',(None,'final_rms'))
    assert len(cohorts)==773
    by_op={(c['layer'],c['op']):i for i,c in enumerate(cohorts)}
    routes=[]
    for c in cohorts[1:]:
        routes.append(dict(producer=c['producer'],rows=149 if c['op']=='lm_head' else 150,cols=c['inner'] if c['kind']=='matrix' else c['columns']*c['heads']))
    sources=[];names={}
    def add(name,rows,cols,width):
        if name in names:
            i=names[name];assert sources[i][1:]==(rows,cols,width),(name,sources[i],rows,cols,width);return i
        names[name]=len(sources);sources.append((name,rows,cols,width));return len(sources)-1
    def xname(layer,op):return f'X/{"global" if layer is None else layer}/{op}'
    for i,c in enumerate(cohorts):add(f'C/{i}',c['rows'],c['columns'],{'matrix':6,'norm':4,'lookup':2}[c['kind']])
    source_routes={}
    for r in routes:
        p=r['producer'];shape=(r['rows'],r['cols']);assert source_routes.get(p,shape)==shape;source_routes[p]=shape
    assert len(source_routes)==602
    for (layer,op),(rows,cols) in sorted(source_routes.items(),key=lambda p:(-1 if p[0][0] is None else p[0][0],p[0][1])):
        add(xname(layer,op),rows,cols,2)
    input_sources=[names[xname(*r['producer'])] for r in routes]
    norms=[]
    for i,c in enumerate(cohorts):
        if c['kind']!='norm':continue
        for weighted in (True,False):
            if not weighted and c['op']!='k_norm':continue
            op=c['op'] if weighted else 'v_norm'
            inp=input_sources[i-1]
            if not weighted and c['layer']%6!=5:
                inp=add(xname(c['layer'],'v_source'),150,c['columns']*c['heads'],2)
            stat=add(f'S/{len(norms)}',c['rows'],1,6)
            out=add(xname(c['layer'],op),c['rows']//c['heads'],c['columns']*c['heads'],2)
            norms.append(dict(layer=c['layer'],op=op,heads=c['heads'],columns=c['columns'],rows=c['rows'],input=inp,stat=stat,output=out,cohort=i if weighted else None))
    assert len(norms)==421 and len(sources)==2146
    assert sum(r*c*w for _,r,c,w in sources)==7091219838
    norm_by={(n['layer'],n['op']):n for n in norms}
    gates=[(i,c) for i,c in enumerate(cohorts) if c['op']=='gate_proj']
    gin=[add(xname(c['layer'],'gate_proj'),c['rows'],c['columns'],2) for i,c in gates]
    gout=[add(xname(c['layer'],'gelu_tanh'),c['rows'],c['columns'],2) for i,c in gates]
    ghist=[add(f'M/GELU/{c["layer"]}',1,65535,4) for i,c in gates]
    up=[add(xname(c['layer'],'up_proj'),c['rows'],c['columns'],2) for i,c in gates]
    guraw=[add(f'R/{c["layer"]}/gate_up_mul',c['rows'],c['columns'],6) for i,c in gates]
    rotations=[n for n in norms if n['op'] in ('q_norm','k_norm')]
    roperaw=[add(f'R/{n["layer"]}/{"q" if n["op"]=="q_norm" else "k"}_rope',150,n['heads']*n['columns'],6) for n in rotations]
    ropeout=[add(xname(n['layer'],('q' if n['op']=='q_norm' else 'k')+'_rope'),150,n['heads']*n['columns'],2) for n in rotations]
    assert len(sources)==2686
    rotation_by={(n['layer'],n['op']=='q_norm'):(raw,out) for n,raw,out in zip(rotations,roperaw,ropeout)}
    attention=[]
    for layer in range(60):
        cols=norm_by[(layer,'q_norm')]['columns']*32
        ids=[add(f'attention/{layer}/{name}',rows,columns,width) for name,rows,columns,width in [('R',8192,old+150,6),('X',8192,old+150,2),('Pi',8192,old+150,2),('Y',150,cols,6)]]
        attention.append(dict(q=rotation_by[layer,True][1],k=rotation_by[layer,False][1],v=norm_by[layer,'v_norm']['output'],raw=ids[0],score=ids[1],pi=ids[2],pvraw=ids[3],pvout=input_sources[by_op[layer,'o_proj']-1]))
    ffwout=[add(xname(l,'ffw_residual_add'),150,5376,2) for l in range(60)]
    ops=[dict(name='global/embedding_scale',inputs=[0],output=norm_by[0,'input_rms']['input'])]
    for l in range(60):
        inp=norm_by[l,'input_rms']['input'];aout=norm_by[l,'pre_ffw_rms']['input']
        out=norm_by[None,'final_rms']['input'] if l==59 else norm_by[l+1,'input_rms']['input']
        ops.extend([dict(name=f'{l}/attention_residual_add',inputs=[inp,norm_by[l,'post_attention_rms']['output']],output=aout),dict(name=f'{l}/ffw_residual_add',inputs=[aout,norm_by[l,'post_ffw_rms']['output']],output=ffwout[l]),dict(name=f'{l}/layer_scalar_mul',inputs=[ffwout[l]],output=out)])
    for op in ops:op['raw']=add('R/'+op['name'],150,5376,6)
    outputraw=by_op[None,'lm_head']
    outputin=add('X/global/lm_head',50,262144,2)
    output=add('X/global/final_tanh_softcap',50,262144,2)
    outputhist=add('M/global/final_tanh_softcap',1,65535,4)
    slack=add('U/global/argmax_slack',50,262144,2)
    soft=[]
    for l in range(60):
        ids=[add(f'softmax/{l}/{name}',rows,cols,width) for name,rows,cols,width in [('max',8192,1,2),('D',8192,old+150,2),('E',8192,old+150,4),('Z',8192,1,6),('M',1,65535,4)]]
        soft.append(dict(max=ids[0],diff=ids[1],exp=ids[2],den=ids[3],hist=ids[4]))
    live=sum(r*c*w for _,r,c,w in sources)
    assert len(sources)==3471 and live==[13154672538,14334320538,15513968538][old//150]
    # Exact public packing; no scalar/witness-sized arrays.
    scalar=[]
    for source,(_,rows,cols,width) in enumerate(sources):
        for row,nrows in intervals(rows):
            for col,ncols in intervals(cols):scalar.append((source,row,col,nrows,ncols))
    scalar.sort(key=lambda t:(-t[3]*t[4],t[0],t[1],t[2]))
    by_source=[[] for _ in sources]
    for i,t in enumerate(scalar):by_source[t[0]].append(i)
    byte=[]
    for i,t in enumerate(scalar):
        for first,width in intervals(sources[t[0]][3]):byte.append((i,first,width))
    byte.sort(key=lambda b:(-scalar[b[0]][3]*scalar[b[0]][4]*b[2],scalar[b[0]][0],scalar[b[0]][1],scalar[b[0]][2],b[1]))
    by_scalar=[[] for _ in scalar];offset=0
    for i,(index,first,width) in enumerate(byte):
        t=scalar[index];size=t[3]*t[4]*width;assert offset%size==0
        byte[i]=(index,first,width,offset);by_scalar[index].append(i);offset+=size
    assert offset==live
    # Build the production initial step vector then stable Kahn order.
    steps=[]
    def step(kind,inputs,outputs,extra=None):steps.append(dict(kind=kind,inputs=inputs,outputs=outputs,extra=extra))
    step('embedding',[],[0])
    for i,c in enumerate(cohorts):
        if c['kind']=='matrix':step('matrix',[input_sources[i-1]],[i])
    for n in norms:step('norm',[n['input']],([] if n['cohort'] is None else [n['cohort']])+[n['stat'],n['output']],n)
    matrix_out={}
    for i,r in enumerate(routes,1):
        raw=by_op.get(r['producer'])
        if raw is not None and cohorts[raw]['kind']=='matrix':matrix_out[raw]=input_sources[i-1]
    for n in norms:
        if n['cohort'] is None and (n['layer'],'v_source') in by_op:matrix_out[by_op[n['layer'],'v_source']]=n['input']
    for (i,c),inp in zip(gates,gin):matrix_out[i]=inp
    for l in range(60):matrix_out[by_op[l,'up_proj']]=up[l]
    matrix_out[outputraw]=outputin
    assert len(matrix_out)==411
    pairs=[(i,matrix_out[i]) for i,c in enumerate(cohorts) if c['kind']=='matrix']
    pairs += [(guraw[l],input_sources[by_op[l,'down_proj']-1]) for l in range(60)]
    pairs += list(zip(roperaw,ropeout))
    pairs += [(a['raw'],a['score']) for a in attention]
    pairs += [(a['pvraw'],a['pvout']) for a in attention]
    pairs += [(op['raw'],op['output']) for op in ops]
    assert len(pairs)==892
    for raw,out in pairs:step('score_rne' if raw in {a['raw'] for a in attention} else 'rne',[raw],[out])
    for op in ops:step('affine',op['inputs'],[op['raw']])
    for l in range(60):
        a=attention[l];s=soft[l]
        step('gelu',[gin[l]],[gout[l],ghist[l]])
        step('gate',[gout[l],up[l]],[guraw[l]])
        step('qk',[a['q'],a['k']],[a['raw']])
        step('softmax',[a['score']],[a['pi'],s['max'],s['diff'],s['exp'],s['den'],s['hist']],s)
        step('pv',[a['pi'],a['v']],[a['pvraw']])
    for n,raw in zip(rotations,roperaw):step('rope',[n['output']],[raw])
    step('softcap',[outputin],[output,outputhist]);step('argmax',[output],[slack])
    owner={source:i for i,s in enumerate(steps) for source in s['outputs']}
    assert len(owner)==len(sources) and sum(len(s['outputs']) for s in steps)==len(sources)
    consumers=[[] for _ in steps];degree=[]
    for i,s in enumerate(steps):
        dep={owner[x] for x in s['inputs']};degree.append(len(dep))
        for p in sorted(dep):consumers[p].append(i)
    ready=deque(i for i,d in enumerate(degree) if d==0);ordered=[]
    while ready:
        i=ready.popleft();ordered.append(i)
        for child in consumers[i]:
            degree[child]-=1
            if degree[child]==0:ready.append(child)
    assert len(ordered)==len(steps)
    frozen={op['output'] for op in ops if op['name']=='global/embedding_scale' or op['name'].endswith('/layer_scalar_mul')}
    assert len(frozen)==61
    hist=set(ghist)|{outputhist}|{s['hist'] for s in soft}
    tails={x for a in attention for x in (a['k'],a['v'])}
    frozen |= hist|tails
    needed=set();pending=list(range(len(sources)))
    while pending:
        source=pending.pop()
        if source in frozen:continue
        i=owner[source]
        if i not in needed:needed.add(i);pending.extend(steps[i]['inputs'])
    emitted=[]
    for i in ordered:
        if i not in needed:continue
        s=steps[i];kind=s['kind']
        firsts=[h*256 for h in range(32)] if kind in ('qk','score_rne','softmax') else [0]
        count=min(sources[s['outputs'][0]][1],150)
        if kind in ('softcap','argmax') or (kind=='matrix' and s['outputs'][0]==outputraw) or (kind=='rne' and s['inputs']==[outputraw]):count=50
        for first in firsts:
            actual=s['outputs']
            if kind=='softmax':
                a=s['extra'];actual=[a['max'],a['diff'],a['exp'],a['den'],s['outputs'][0]]
            for source in actual:
                if source in frozen:continue
                row,nrows=first,count
                if kind=='norm' and source!=s['extra']['output']:
                    row*=s['extra']['heads'];nrows*=s['extra']['heads']
                emitted.append((source,row,nrows,'live'))
    padding={a[k] for a in attention for k in ('raw','score','pi')}|{s[k] for s in soft for k in ('max','diff','exp','den')}
    for source,(_,rows,cols,width) in enumerate(sources):
        if source in frozen:
            emitted.append((source,0,150 if source in tails else rows,'frozen'))
        elif source in padding:
            for head in range((rows+255)//256):
                first=head*256+150
                if first<rows:emitted.append((source,first,min(rows-first,106),'pad'))
    return sources,scalar,byte,by_source,by_scalar,emitted,live,len(steps),len(needed)


class Frontier:
    """Independent sorted interval union; owner capacity is checked after union."""
    def __init__(self):self.spans=[];self.highwater=0;self.at_highwater=None;self.visited=0;self.events=0
    def insert(self,first,last,context):
        pos=bisect.bisect_left(self.spans,(first,))
        assert not (pos and self.spans[pos-1][1]>first),('overlap-left',context,first,last)
        assert not (pos<len(self.spans) and self.spans[pos][0]<last),('overlap-right',context,first,last)
        self.visited+=last-first;self.events+=1
        if pos and self.spans[pos-1][1]==first:
            pos-=1;first=self.spans[pos][0];self.spans.pop(pos)
        if pos<len(self.spans) and self.spans[pos][0]==last:last=self.spans.pop(pos)[1]
        self.spans.insert(pos,(first,last))
        if len(self.spans)>self.highwater:self.highwater=len(self.spans);self.at_highwater=context


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path('/home/okrame/projects/volta-zk'));args=ap.parse_args()
    reports=[]
    for old in (0,150,300):
        sources,scalar,byte,by_source,by_scalar,emitted,live,steps,needed=build(args.root,old)
        frontier=Frontier();rows_seen=[Frontier() for _ in sources]
        for source,first,count,phase in emitted:
            name,rows,cols,width=sources[source];assert count and 0<=first<first+count<=rows
            rows_seen[source].insert(first,first+count,(source,name,phase))
            for index in by_source[source]:
                _,row,col,nrows,ncols=scalar[index];lo=max(first,row);hi=min(first+count,row+nrows)
                if lo>=hi:continue
                for bi in by_scalar[index]:
                    _,bfirst,bwidth,offset=byte[bi]
                    start=offset+(lo-row)*ncols*bwidth
                    frontier.insert(start,start+(hi-lo)*ncols*bwidth,(source,name,first,count,bfirst,bwidth,phase))
        assert all(v.spans==[(0,sources[i][1])] for i,v in enumerate(rows_seen)),[(i,sources[i],v.spans) for i,v in enumerate(rows_seen) if v.spans!=[(0,sources[i][1])]][:8]
        assert frontier.spans==[(0,live)] and frontier.visited==live
        reports.append(dict(old=old,sources=len(sources),scalar_tiles=len(scalar),byte_tiles=len(byte),producer_steps=steps,needed_steps=needed,source_row_events=len(emitted),tile_interval_events=frontier.events,live=live,frontier_highwater=frontier.highwater,at_highwater=frontier.at_highwater,capacity4096_admitted=frontier.highwater<=4096,complete=True))
    hashes={name:hashlib.sha256((args.root/name).read_bytes()).hexdigest() for name in ['manifests/c7-d126-gemma31b-qspec-dag-v1.json','manifests/c7-d126-gemma31b-source-metadata-v1.json']}
    print('C71_SOURCE_FRONTIER_PINNED_METADATA '+json.dumps(dict(cases=reports,inputs_sha256=hashes,scope='Independent metadata replica; no source values, W/A, CUDA or PCG execution',gpu_execution=False,credit=False),sort_keys=True))
    assert all(case['capacity4096_admitted'] for case in reports), 'Public canonical source schedule exceeds the fixed owner frontier'


if __name__=='__main__':main()

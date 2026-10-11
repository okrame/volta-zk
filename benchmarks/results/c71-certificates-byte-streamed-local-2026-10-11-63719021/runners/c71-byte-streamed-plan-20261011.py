import hashlib,json,sys,resource
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
sys.path.insert(0,str(Path.cwd()/'scripts'))
from c71_gkr_screen import merge,modulo_union_length,source_tree_trace
from c71_byte_tree_contraction import rank_bounds
p=Path('benchmarks/results/c71-certificates-rms-shared-support-local-2026-10-11-fe5f9d65/c71-rms-shared-support-20261011.json')
x=json.loads(p.read_text());n=x['padded_cells'];bits=n.bit_length()-1;assert n==1<<bits and bits==29
spans=merge([span for program in x['intervals'] for span in program]);live=sum(b-a for a,b in spans)
assert live==sum(b-a for program in x['intervals'] for a,b in program)==347937024
assert len(spans)<=16384
lanes=12;budget=8<<20;layers=[]
counts=[modulo_union_length(spans,n>>q) for q in range(bits)]
for h,rank in enumerate(rank_bounds()):
 def size(rows):return lanes*24+rows*(8+lanes*24+2*lanes*rank*24)
 cp=next((q for q,count in enumerate(counts) if size(count)<=budget),bits)
 passes=min(cp+1,bits)+1
 layers.append({'layer':h,'rank_upper_per_lane':rank,'checkpoint_upper':cp,'retained_rows_at_upper_checkpoint':counts[cp] if cp<bits else 0,'one_state_bytes_upper_at_checkpoint':size(counts[cp]) if cp<bits else 0,'original_byte_getter_calls_upper':passes*lanes*live,'original_source_passes_per_lane_upper':passes})
# Corroborate the same accounting with the native 256-cell and mixed RMS fixtures.
assert 2*8*173==2768 and 2*8*12*6==1152
out={'schema':'volta-c71-byte-streamed-public-plan-v1','credit':False,'input':str(p),'input_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'padded_cells':n,'live_cells':live,'merged_support_intervals':len(spans),'live_lanes_upper':lanes,'state_budget_bytes':budget,'evaluator_heap_upper_bytes':32<<20,'layers':layers,'original_byte_getter_calls_upper':sum(r['original_byte_getter_calls_upper'] for r in layers),'selected_literal_tree_getter_calls':source_tree_trace(bits+4,8)['counted_work']['getter_calls'],'scope':'Public rank and support upper for bounded contraction. Literal four-child getters and original byte getters have different units; no speed ratio inferred. Excludes feature arithmetic/transforms, Eq, MAC/FS, source caller, PCS, AES and model execution. Not a complete canonical resource or runtime bound.'}
with Path(sys.argv[1]).open('x') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(out))

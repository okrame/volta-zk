#!/usr/bin/env python3
"""Bounded source census and campaign plan; no execution or performance credit.

Reads the named revision, never weights/private values, and launches no test,
compiler, provider or GPU. Root may run this under the local 60s/2GiB limits.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = 'HEAD'
PCS = 'rust/volta-pcs/src/c71_matrix/'
FILES = {
    PCS+'b12.rs': ['round.num_queries = 512', 'result.inner.final_queries = 512'],
    PCS+'b12/replay_tree.rs': ['const CANONICAL_QUERY_ROWS: usize = 1 << 20',
        'needed.dedup()', 'needed.chunks(batch_cap / self.cut)',
        'subtree * self.cut..(subtree + 1) * self.cut', '(self.row)(&batch_indices)'],
    PCS+'b12/replay.rs': ['indices.len().next_power_of_two()',
        'let source_rows=if split {active} else {n+pad_rows}',
        'let blocks=(n+pad_rows).div_ceil(cap)', 'for limb in 0..3',
        'native_d2d_bytes', 'native_launches', 'native_fences'],
    'cuda/c71_pcs_query.cu': ['if(degree<=8)', 'reverse_high<<<',
        'multiply_factor<<<', 'reverse_quotient<<<', 'subtract_product<<<'],
    'cuda/c71_fft.cuh': ['launch_five_pass', 'launch_odd', 'launch_natural',
        'parity_scatter_kernel<<<', 'cudaMemcpyDeviceToDevice', 'std::min(32767u'],
    PCS+'range/windowed.rs': ['const WINDOWS:', 'const W_WINDOWS:',
        'Alphabet::Symmetric(_) => (11, 1usize << 27'],
    PCS+'range/windowed/native.rs': ['self.work.source_passes += 1',
        'self.work.requested_bytes +=', 'BEFORE the GKR caller'],
    'rust/volta-pcg/src/c71_bootstrap.rs': ['let cipher = Aes256::new_from_slice',
        'cipher.encrypt_blocks(&mut blocks)', 'work.aes_key_schedules += 1',
        'work.aes_block_encryptions += 4'],
    'rust/volta-pcg/src/c71_seed6/real.rs': ['factor * 384 * rows * height',
        'factor * 384 * rows * height * 4'],
    PCS+'gemma/native/canonical_runner.rs': ['installation_w_commitment', 'seed6_setup',
        'wait_and_decode_response', 'verify_journal_and_completion'],
    PCS+'gemma/native/canonical_state.rs': ['preparation_including_inference',
        'commitment_a', 'proof_body', 'exchange_and_completion'],
    PCS+'gemma/native/canonical_prove.rs': ['rms.prove_rms(s, &self.recipes.rms, &read, fs, rows)'],
    PCS+'gemma/rms/caller.rs': ['gkr::prove(&gs, |i| frames.frame(i).unwrap(), fs, &mut rows)',
        'CompactFrames::build', 'report["rms_parameters"]'],
    PCS+'rms/gkr.rs': ['prove_impl(s, &get_frame, fs, correlations, true, None)',
        'prove_sourcewise(s, get_frame, fs, correlations)', 'byte_function::prove_sourcewise(',
        'source_cell_round::<true>', 'if !present[program_index]'],
    PCS+'byte_function.rs': ['prove_sourcewise_impl(s, original, get_byte, fs, correlations, false, &[], 0)',
        'range::prove_tree_sourcewise_custom('],
    'cuda/c71_range_runtime.cpp': ['if(fence(c)) return -1;',
        'if(c71_range_release(c,x) || (y && c71_range_release(c,y))) return -1;',
        'return c71_range_release(c,id);', 'c->stats.h2d_bytes+=bytes;'],
}

def source(path):
    return subprocess.check_output(['git', 'show', BASELINE+':'+path], cwd=ROOT, text=True)

def align(n):
    return (n+255)//256*256

def ceil(n, d):
    return (n+d-1)//d

def natural_launches(log, batch=1):
    scatter = int(log>1 and log%2==1)
    per_group = 5 if log%2==0 else (1 if log==1 else 6)
    return scatter+ceil(batch,32767)*per_group

def remainder_launches(degree, count):
    return 1 if degree<=8 else 5+4*natural_launches((2*degree).bit_length()-1,count//degree)

def public_query_arrays(q):
    assert q>0 and q&(q-1)==0
    degrees=[1<<i for i in range(q.bit_length())]
    # Each Newton doubling performs two products, each product three DFTs.
    # Product lengths are3t-1: size2 for t1, otherwise4t. Tree merges
    # multiply degree-d factors at transform size4d. Count calls/cells,
    # not butterflies, instructions or CPU-time from a different binary.
    newton_products=newton_cells=0
    for degree in degrees:
        for j in range(1,degree.bit_length()):
            size=2 if j==1 else 1<<(j+1)
            newton_products+=2*(q//degree)
            newton_cells+=6*size*(q//degree)
    tree_cells=sum(3*4*d*(q//(2*d)) for d in degrees[:-1])
    return {'spectra_bytes': 2*len(degrees)*align(16*q),
        'twiddle_bytes': 2*sum(align(16*d) for d in degrees),
        'spectrum_DFT_calls': 2*sum(q//d for d in degrees),
        'spectrum_DFT_cells': 4*q*len(degrees),
        'product_tree_merges': q-1,
        'Newton_polynomial_products':newton_products,
        'Newton_DFT_calls':3*newton_products,'Newton_DFT_cells':newton_cells,
        'product_tree_DFT_calls':3*(q-1),'product_tree_DFT_cells':tree_cells,
        'total_public_factor_DFT_calls':2*sum(q//d for d in degrees)+3*newton_products+3*(q-1),
        'total_public_factor_DFT_cells':4*q*len(degrees)+newton_cells+tree_cells,
        'spectrum_upload_fences':2*len(degrees),
        'public_arrays_release_fences':4*len(degrees),
        'twiddle_generation_GPU_launches':2*len(degrees),
        'excluded': 'DFT internal butterflies/cache, points/shift exponentiation, CPU staging/copies/allocator, packets/private pad/flag'}

def opening_batches(unique_subtrees, cut=4096, cap=1<<20):
    assert 1<=unique_subtrees<=512 and cut<=cap and cap%cut==0
    return [{'subtrees': min(cap//cut,unique_subtrees-i),
        'rows': cut*min(cap//cut,unique_subtrees-i),
        'q_eff': 1<<(cut*min(cap//cut,unique_subtrees-i)-1).bit_length()}
        for i in range(0,unique_subtrees,cap//cut)]

def initial_query(live, dimension, q):
    width=128; n=(1<<dimension)//width; pads=1536
    active=[max(0,min(n,live-c*n)) for c in range(width)]
    main=sum(ceil(a if a<n else n+pads,q) for a in active)
    split=sum(a<n for a in active)
    return {'q_eff':q,'main_root_blocks':main,
        'main_remainder_kernel_launches':main*remainder_launches(q,q),
        'main_low_loader_launches':main,
        'main_odd_fft_packing_D2D_bytes':main*64*q if (2*q).bit_length()%2==0 else 0,
        'pad_split_columns':split,'pad_extra_root_remainders':split*((ceil(pads,q) if pads>q else 0)+1),
        'pad_note': 'when pads<=q native has no pad-Horner block; only shift+one remainder; CPU direct pad initialization',
        'child_level_launches':width*sum(remainder_launches(1<<i,q) for i in range(q.bit_length()-1)),
        'final_matrix_D2H_bytes':width*q*8,
        'public_query_arrays':public_query_arrays(q),
        'excluded': 'pad shift/add/load, original-window producer/gather, allocations/releases/fences, all kernel HBM loads/stores, CPU Merkle'}

def extension_query(dimension_after_first_fold,q):
    n=(1<<dimension_after_first_fold)//4; blocks=ceil(n+512,q)
    nontrivial=12*(blocks-1)
    return {'blocks_per_E_column':blocks,'source_loads_three_limbs':4*blocks,
        'root_remainder_calls':nontrivial,'first_block_D2D_bytes':12*q*8,
        'root_remainder_kernel_launches':nontrivial*remainder_launches(q,q),
        'odd_fft_packing_D2D_bytes':nontrivial*64*q,
        'child_level_launches':12*sum(remainder_launches(1<<i,q) for i in range(q.bit_length()-1)),
        'final_matrix_D2H_bytes':96*q+16,'minimum_query_begin_and_finish_fences':8,
        'host_publication_payload_bytes':144*q,'named_device_arrays_bytes':
            public_query_arrays(q)['spectra_bytes']+public_query_arrays(q)['twiddle_bytes']+
                align(24*q)+4*align(8*q)+2*align(16*q),
        'excluded': 'EQ/pads metadata and flag; all producers/kernels HBM, release fences, factor construction CPU'}

def window_lengths(text,name):
    match=re.search(r'const '+name+r':.*?=\s*(\[.*?\]);',text,re.S)
    assert match, name
    return [len(re.findall(r'\d+',window)) for window in re.findall(r'&\[([^\]]*)\]',match[1])]

def range_census(bits,cut,lengths,window,bytes_per_word):
    assert len(lengths)==cut
    passes=1+sum(1+length for length in lengths)
    rounds=bits*(bits-1)//2
    retained=bits-cut
    h_rounds=sum(range(cut))
    # Child coefficients use two scratch buffers iff remainingbits>=10;
    # download fences once, then generic release fences each buffer again.
    second_scratch=sum(max(0,min(layer,retained)-9) for layer in range(bits))
    coefficient_fences=2*rounds+second_scratch
    gram_release_fences=sum(range(cut))+sum(lengths)
    source_release_fences=passes*(1<<bits)//window if bytes_per_word==1 else passes
    upload_fences=0 if bytes_per_word==1 else passes*(1<<bits)//window
    return {'virtual_full_source_passes':passes,'virtual_window_requests':passes*(1<<bits)//window,
        'logical_requested_bytes':passes*(1<<bits)*bytes_per_word,
        'coefficient_rounds':rounds,'coefficient_D2H_bytes':96*rounds,
        'coefficient_dependency_fences':rounds,'terminal_D2H_bytes':96*bits,
        'root_D2H_bytes':48,'H_coefficient_rounds':h_rounds,
        'coefficient_scratch_release_fences':rounds+second_scratch,
        'coefficient_API_total_fences':coefficient_fences,
        'root_and_terminal_download_fences':bits+1,
        'canopy_and_retained_children_release_fences':bits+1,
        'Gram_bucket_fold_and_final_release_fences':gram_release_fences,
        'source_window_release_fences':source_release_fences,'W_signed_upload_fences':upload_fences,
        'known_consumer_success_path_fences':coefficient_fences+2*(bits+1)+gram_release_fences+source_release_fences+upload_fences,
        'excluded': 'resident A producer/byte-seal flags/fences, numeric staging, allocation/close, kernel HBM and partial A replay costs'}

def real_seed6(n):
    rows=n+6; h=(rows-1).bit_length(); outputs=3*384*rows
    return {'seed_rows':n,'blinded_rows':rows,'height':h,'both_roles_AES_field_outputs':outputs,
        'both_roles_AES256_key_schedules':outputs*h,
        'both_roles_AES256_block_encryptions':4*outputs*h,
        'both_roles_wire_bytes':146491+3120*n,
        'excluded': 'MR19 group operations, SHAKE samplers, compression/seal, Dory/cGGM/equality expansion, transport/journal'}

def self_check():
    assert opening_batches(512)==[{'subtrees':256,'rows':1<<20,'q_eff':1<<20}]*2
    assert [x['q_eff'] for x in opening_batches(257)]==[1<<20,4096]
    assert [x['q_eff'] for x in opening_batches(385)]==[1<<20,1<<20]
    assert natural_launches(21)==7 and natural_launches(10)==5
    assert remainder_launches(1<<20,1<<20)==33 and remainder_launches(512,512)==25
    assert public_query_arrays(1<<20)['twiddle_bytes']==67110400
    assert public_query_arrays(1<<20)['spectra_bytes']==704643072
    assert extension_query(28,1<<20)['named_device_arrays_bytes']==864028160
    assert initial_query(30697345280,35,1<<20)['main_root_blocks']==29390
    assert [initial_query(a,34,1<<20)['main_root_blocks'] for a in
        [13154672538,14334320538,15513968538]]==[12644,13777,14911]
    assert public_query_arrays(1)['total_public_factor_DFT_calls']==2
    assert public_query_arrays(2)['total_public_factor_DFT_calls']==15
    assert public_query_arrays(1<<20)['total_public_factor_DFT_calls']==19922807
    assert public_query_arrays(1<<20)['total_public_factor_DFT_cells']==679477284
    assert range_census(34,10,[0,1,1,1,1,1,2,2,3,3],1<<30,1)['known_consumer_success_path_fences']==1923
    assert range_census(35,11,[0,1,1,1,1,1,2,2,2,3,3],1<<27,2)['known_consumer_success_path_fences']==9057

def admitted_rms_work():
    selected_gkr = source(PCS+'rms/gkr.rs')
    boolean_first_round = 'boolean_first_round_gate_products_saved' in selected_gkr
    packed_replay = 'patterns::PackedReplay::new' in selected_gkr
    ledger_path='artifact/c7.1-pod/ledger-20261007T150200Z/ledger-attention.json'
    admission_path='artifact/c7.1-pod/gamma-admission-20261007T155133Z/admission.json'
    recipes_path='artifact/c7.1-pod/ledger-20261007T150200Z/recipes-attention.json'
    raw=(ROOT/ledger_path).read_bytes(); ledger=json.loads(raw)
    admission_raw=(ROOT/admission_path).read_bytes(); admission=json.loads(admission_raw)
    recipes_raw=(ROOT/recipes_path).read_bytes(); recipes=json.loads(recipes_raw)
    evidence={entry['path']:entry['sha256'] for entry in admission['evidence']}
    assert admission['gamma_admitted'] is True
    assert hashlib.sha256(raw).hexdigest()==evidence[ledger_path]
    assert ledger['candidate_sha256']==evidence['artifact/c7.1-pod/pilot-complete-20261007T133500Z/pilot-fp64-full/candidate.json']
    assert ledger['recipe_digest']==recipes['recipe_digest']
    rows=[]
    for context in ledger['contexts']:
        rms=context['rms']; cell=context['rms_source_prover']['cell_phase']; support=context['rms_structural_support']
        assert rms['rms_parameters']==recipes['rms']
        assert bytes(rms['profile_digest']).hex()==ledger['recipe_digest']
        bits=rms['padded_cells'].bit_length()-1
        assert cell['cell_first_logical_frame_callbacks']==rms['live_cells']*bits*rms['depth']
        pairs=sum(profile['supported_pairs'] for r in support['rounds'] for profile in r['profiles'])
        ops=support['supported_gate_iterations_all_rounds']; program_pairs=pairs*rms['depth']
        core={'Fp3_mul':7*(ops['and']+ops['xor'])+2*ops['copy']+6*program_pairs,
            'Fp3_add':4*ops['and']+9*ops['xor']+2*ops['copy']+6*program_pairs,
            'Fp3_sub':2*ops['and']+4*ops['xor']+ops['copy']+program_pairs,'Fp3_neg':ops['xor']}
        assert core==support['factored_arithmetic_after_structural_support_pruning']
        first = {op:sum(p['gate_iterations_across_layers'][op]
                        for p in support['rounds'][0]['profiles'])
                 for op in ('and','xor','copy')}
        saved = 7*(first['and']+first['xor'])+2*first['copy'] if boolean_first_round else 0
        selected_core = dict(core)
        if boolean_first_round:
            selected_core['Fp3_mul'] -= saved
            selected_core['Fp3_add'] += 5*first['and']+2*first['copy']
            selected_core['Fp3_sub'] += first['and']-first['xor']
            selected_core['Fp3_neg'] -= first['xor']
        assert all(v >= 0 for v in selected_core.values())
        assert sum(layer['scalar_boolean_replay_gate_evaluations'] for layer in rms['layers'])==cell['cell_first_scalar_boolean_replay_gates']
        rows.append({'old_tokens':context['old_tokens'],'programs':rms['programs'],
            'depth':rms['depth'],'live_cells':rms['live_cells'],'padded_cells':rms['padded_cells'],
            'cell_sumcheck_rounds':bits*rms['depth'],'cell_phase':cell,
            'gate_iterations_after_public_support_pruning':ops,'coefficient_core_Fp3':core,
            'coefficient_core_Fp3_scope':'immutable historical baseline; selected route is separate',
            'selected_coefficient_core_Fp3':selected_core,
            'selected_boolean_first_round_products_saved':saved,
            'selected_boolean_first_round_scope':'exact source-operation count on public structural support; no timing or instruction credit',
            'byte_endpoint_children_source_work':context['rms_source_prover']['byte_endpoint']['counted_work'],
            'compact_frames_named_payload_and_metadata_bytes':rms['compact_original_PYS_candidate']['payload_and_metadata_bytes'],
            'missing':context['rms_source_prover']['missing']})
    assert [row['old_tokens'] for row in rows]==[0,150,300]
    return {'status':'quantified partial source work on admitted Gamma; no instruction/time lower bound',
        'Gamma_admission_verified_by_ledger_digest':True,'ledger':ledger_path,
        'ledger_sha256':hashlib.sha256(raw).hexdigest(),'admission':admission_path,
        'admission_sha256':hashlib.sha256(admission_raw).hexdigest(),'recipes':recipes_path,
        'recipes_sha256':hashlib.sha256(recipes_raw).hexdigest(),'recipe_digest':ledger['recipe_digest'],
        'historical_ledger_flags_preserved':{'calibrated':ledger['calibrated'],'complete_work':ledger['complete_work'],
            'complete_physical_peak':ledger['complete_physical_peak'],'credit':ledger['credit']},
        'selected_route':'canonical_prove -> caller.prove_rms -> gkr.prove -> prove_sourcewise -> prove_impl(true,None); no pattern histogram; canonical byte endpoint sourcewise',
        'selected_boolean_first_round_masks':boolean_first_round,
        'selected_packed_replay':packed_replay,
        'packed_replay_scope':'64 original cells per packet, one disjoint live mask per present program; mixed packets may have no 64x sharing. Historical scalar gate counts are not selected packed counts',
        'frame_callback_scope':'CompactFrames cache reads/replay; not additional complete A reconstructions',
        'contexts':rows,'excluded_other_nonrange_families':['RMS statistic/P0','RNE/tableRNE','gate/Rope/QK/PV claims',
            'EXP30 maximum/lookup/ratio pattern branch','GELU/softcap lookup','index/terminal/MAC/FS/codec/verifier'],
        'target_status':'structural dominant CPU work remains open; H100 profiling alone does not close or accelerate this route',
        'minimum_native_candidate':'reuse common owner, MAC-u3=2 arithmetic/reduction and bounded CompactFrames chunks; add RMS Boolean replay+four-coefficient consumer and byte-LUT consumer, preserving index/MAC/FS order and joint cap. No existing drop-in kernel; no candidate selected or performance inferred',
        'new_campaign_requirement':'time and count selected RMS cell/byte consumers separately with current Gamma, exact coefficient/wire/MAC parity, both-role CPU profiles and complete scratch/caches; remaining named families need their own counters before complete work/time claim'}

def existing_records():
    names=['c71-cuda-experiment-2026-10-07-868a3e8.json',
        'c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json',
        'c71-crypto-linear-local-2026-10-09-31280382f681.json',
        'c71-crypto-residual-query-local-2026-10-09-9a5da712a258.json']
    rows=[]
    for name in names:
        path=ROOT/'benchmarks/results'/name; raw=path.read_bytes(); record=json.loads(raw)
        row={'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),
            'source_git_sha':record.get('source_git_sha',record.get('git_sha')),
            'git_dirty':record.get('git_dirty'),'status':record.get('status'),
            'scope':'reused immutable evidence; not a new run or current canonical phase measurement'}
        if 'residual-query' in name:
            row['finite_full_WHIR_tests']=[{'filter':check.get('name'),
                'wall_s':check.get('wall_s'),'max_rss_bytes':check.get('max_rss_bytes'),
                'exit_code':check.get('exit_code'),'scope':'D10 whole parity fixture, RustO0 and fakeCUDA; includes CPUreference/verification'}
                for check in record['checks'] if '_full_whir_' in check.get('name','')]
        rows.append(row)
    return rows

def report():
    provenance={}; texts={}
    for path,anchors in FILES.items():
        text=source(path); texts[path]=text
        for anchor in anchors: assert anchor in text, (path,anchor)
        provenance[path]={'sha256':hashlib.sha256(text.encode()).hexdigest(), 'anchors':anchors}
    self_check()
    wt=texts[PCS+'range/windowed.rs']; q=1<<20
    responses=[]
    for old,live in [(0,13154672538),(150,14334320538),(300,15513968538)]:
        products=2*32*(150*old+150*151//2)*(50*256+10*512)
        responses.append({'old_tokens':old,'A_live_bytes':live,
            'full_A_scans_lower_bound':512+35+34,
            'lower_bound_scope':'initial commitment512 + singleton/S1/OOD/retention35 + linear34; excludes partial range/query/CPU-GKR requests',
            'QK_plus_PV_causal_integer_products_per_full_A_scan':products,
            'QK_plus_PV_products_at_full_scan_lower_bound':products*581,
            'initial_query_per_q2p20_batch':initial_query(live,34,q)})
    return {'schema':'c71-residual-source-profile-v1','source_git_sha':BASELINE,
        'classification':'source arithmetic and proposed procedure; no newly measured GPU/complete canonical results',
        'credit':False,'gpu_execution':False,'joint_admitted':False,'provenance':provenance,
        'reused_records':existing_records(),
        'pinned_input_counts_provenance':'active specs and canonical getter metadata, bytes not sampled from private sources',
        'W_installation':{'equivalent_live_scans':128,'logical_live_i16_bytes':61394690560,
            'logical_read_bytes':128*61394690560,'minimum_XOF_prescan_and_replay_bytes':1<<38},
        'responses':responses,
        'nonrange_GKR_admitted_RMS':admitted_rms_work(),
        'opening':{'protocol_queries':512,'distinct_leaves':True,'unique_subtrees':'U = len(set(index//4096))',
            'batch_formula':'at most256 subtrees/batch; q_eff=nextpow2(4096*subtrees_in_this_batch)',
            'maximum_512_subtree_batches':opening_batches(512),
            'small_tail_257_subtrees':opening_batches(257),
            'CPU_Merkle_compressions_per_256_subtree_batch':
                {'initial':(1<<20)*18+256*4095*2,'extension':(1<<20)*3+256*4095*2},
            'caution':'q512 direct evaluation is not sufficient: Merkle regeneration requires all4096 rows/subtree; costs below are per batch and no claimU512 is measured'},
        'initial_W_query_per_q2p20_batch':dict(initial_query(30697345280,35,q),
            execution=('resident original W with shared GPU remainder route' if 'self.native_query=Some(NativeQuery::Weights(native.clone()))' in texts[PCS+'b12/replay.rs'] else 'CPU source; GPU remainder counts conditional')),
        'S1_query_per_q2p20_batch':{'W':extension_query(28,q),'A':extension_query(27,q)},
        'range':{'W':range_census(35,11,window_lengths(wt,'W_WINDOWS'),1<<27,2),
            'A':range_census(34,10,window_lengths(wt,'WINDOWS'),1<<30,1)},
        'real_AES_setup':{'main':real_seed6(17553),'opposite_equality':real_seed6(2025),
            'note':'exact current AES-COPE path work; not old SHAKE candidate cGGM credited as AES'},
        'wire_body_bounds_bytes':{'O0':[47841180,65053244],'O150':[54868318,78945726],
            'O300':[61797384,92723304]},
        'phase_measurement_status':{phase:None for phase in ['installation','setup','inference','proof','verification']},
        'phase_note':'canonical diagnostic stopped during old W commitment; reduced test wall includes oracles, fake driver/compiler and often verifier, so cannot fill canonical phase times',
        'target_obstacle':'response wire lower bounds exceed40MB after first response; cannot claim that target under unchanged protocol',
        'local_plan':LOCAL_PLAN,'hardware_matrix':HARDWARE_MATRIX}

LOCAL_PLAN = [
    {'filter':'c71_b12_query_factors_balanced_product_and_newton_match_direct_oracle',
        'component':'public products/Newton q1..1024','phase':'proof','timing_scope':'whole parity test, not isolated production factor time'},
    {'filter':'c71_b12_query_small_remainders_exact_fp3_and_cost',
        'component':'direct tiny vs former four FFT, same binary128Ki/cap iterations','phase':'proof',
        'timing_scope':'C71_QUERY_SMALL_REMAINDERS internal timing marker, finite CPU only'},
    {'filter':'c71_b12_windowed_native_shared_resident_transcript_original_mac',
        'component':'range D10 live731, original MAC and owner stats','phase':'proof',
        'timing_scope':'simulated driver algebra/lifecycle; no CUDA timing'},
    {'filter':'c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals',
        'component':'real AESSeed6 reduced setup/proof/verify/journal','phase':'setup+proof+verification',
        'timing_scope':'whole reduced2role test; isolated phase markers unavailable, report incomplete'},
    {'filter':'c71_b12_native_canonical_wire_body_geometry',
        'component':'pinned metadata body lower/upper, no valid certificate','phase':'proof+verification codec',
        'timing_scope':'syntactic fixture only'},
]

HARDWARE_MATRIX = [
    {'component':'W initial commitment','compare':'ordinary exacti128 vs Tensor limb16 on same32coset/8column owner',
        'shapes':'reduced ragged signed endpoints,pads,then pinned mapping boundedband',
        'accept':'exact values/root/salts/transcript + joint memory, equivalent128scans; same process/source/compiler; no selection from host parity alone'},
    {'component':'QK/PV','compare':'scalar exact vs MMA exact with causal prefix/common block+scalar tail',
        'shapes':'O0/150/300 rows150,heads32,width256/512; also inference1row and partial replay selectedtargets',
        'accept':'all rawi48/RNE bytes, INT16MIN invalid endpoints, nofuturecolumns, same reconstructedAcount; time entire producer scans separately'},
    {'component':'initial and extension query','compare':'current natural oddFFT packing vs bounded optimized FFT/kernelfusion candidate only after actualprofile',
        'shapes':'512WHIR leaves expanded4096subtrees; qeff4096,512Ki,1Mi and secondbatch; W/A initial+S1',
        'accept':'exact rows/order/duplicates/pads/root/MAC+sameU/cut/batches; accountfactorCPU and1GiB initialD2H/batch, D2D and actualkernelHBM separately'},
    {'component':'synchronization/CUDA Graph','compare':'only repeated public-shape within fixed consumer round or remainder block',
        'gate':'profile launch CPUtime and fences; no Graph crosses FS challenge, outputflag, NoPeek coin phase or terminalcleanup; capture/workspace charged'},
    {'component':'TMA/fusion','compare':'only if kernel profile shows memory/reload costs in W limbtiles or QK/PV sharedtile',
        'gate':'exactinteger equivalence + shared/register/spill/TMA descriptor accounting; no protocol/work reduction claimed'},
    {'component':'CPU residual','compare':'publicfactors, realAESsetup+PCG consume, nonrangeGKR/MAC, codec, verifier, journal each timed separately',
        'gate':'fresh one-use correlations/journals; Γ reuse identity verified; CPUworkcounter profilesnotfakeGPUclaim'},
]

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=pathlib.Path)
    parser.add_argument('--source-sha',default='HEAD')
    parser.add_argument('--repo-root',type=pathlib.Path,default=ROOT)
    args=parser.parse_args(); ROOT=args.repo_root.resolve()
    BASELINE=subprocess.check_output(['git','rev-parse',args.source_sha],cwd=ROOT,text=True).strip()
    result=report()
    encoded=json.dumps(result,indent=2)+'\n'
    if args.output:
        with args.output.open('x') as output: output.write(encoded)
    else: print(encoded,end='')

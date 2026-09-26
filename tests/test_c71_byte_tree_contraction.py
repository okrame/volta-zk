from test_c71_whir_trace import Fp3, eq_table
import c71_byte_tree_contraction as contraction


def inverse(x):
    assert x != 0
    return x**(97**3-2)


def folded(rows, prefix):
    for r in prefix:
        half = len(rows)//2
        rows = [[a+r*(b-a) for a,b in zip(lo,hi)] for lo,hi in zip(rows[:half],rows[half:])]
    return rows


def selector(point, value):
    result, one = Fp3(1), Fp3(1)
    for r,x in zip(point,value): result *= r*x+(one-r)*(one-x)
    return result


def test_public_quadratic_form_handles_singular_and_offdiagonal_pivots():
    zero, a = Fp3(), Fp3(3,5,7)
    for matrix in ([[zero]*3 for _ in range(3)], [[zero,a],[a,zero]],
                   [[a,a,a],[a,a,a],[a,a,a]]):
        factors = contraction.diagonalize(matrix,inverse)
        assert len(factors) <= len(matrix)
        for i,row in enumerate(matrix):
            for j,want in enumerate(row):
                assert sum((d*v[i]*v[j] for d,v in factors),zero) == want


def test_node_contraction_preserves_cell_cubics_and_original_child_values():
    zero, one = Fp3(), Fp3(1)
    cell_point = [Fp3(4,2,3),Fp3(8,9,7),Fp3(11,13,17)]
    challenges = [Fp3(19,23,29),zero,one]
    lane_eq = eq_table([Fp3(31,37,41)])
    lam = Fp3(43,47,53)
    live = [i%4<2 for i in range(8)]  # Public padding, independent of private zeros.
    for alphabet_bits in (3,4):
        n = 1 << alphabet_bits
        bytes_by_lane = [[(5*i+lane*3)%n if live[i] else 0 for i in range(8)] for lane in range(2)]
        coefficients = [[Fp3(2+j+lane,3+2*j,5+j*j) for j in range(n)] for lane in range(2)]
        for layer in range(alphabet_bits):
            node_eq = eq_table([Fp3(7+i,11,13) for i in range(layer)])
            specs = [contraction.contract(c,layer,node_eq,lam,inverse) for c in coefficients]
            original = [[[contraction.evaluate(p,zero+b) for p in spec['children']]
                         for b in values] for spec,values in zip(specs,bytes_by_lane)]
            features = [[[table[b] for _,table in spec['features']] for b in values]
                        for spec,values in zip(specs,bytes_by_lane)]
            for r in range(3):
                dense = [folded(rows,challenges[:r]) for rows in original]
                compact = [folded(rows,challenges[:r]) for rows in features]
                support = live[:]
                for _ in range(r):
                    split = len(support)//2
                    support = [a or b for a,b in zip(support[:split],support[split:])]
                baseline = [sum((d*table[0]*table[0] for d,table in spec['features']),zero) for spec in specs]
                half = 1 << (2-r)
                for trial in [zero,one,Fp3(2),Fp3(3),Fp3(59,61,67)]:
                    want = zero
                    got = selector(cell_point[:r+1],challenges[:r]+[trial])*sum(
                        (w*b for w,b in zip(lane_eq,baseline)),zero)
                    for tail in range(half):
                        tail_bits = [zero+((tail>>j)&1) for j in reversed(range(2-r))]
                        weight = selector(cell_point,challenges[:r]+[trial]+tail_bits)
                        for lane,spec in enumerate(specs):
                            child = [a+trial*(b-a) for a,b in zip(dense[lane][tail],dense[lane][tail+half])]
                            for j,w in enumerate(node_eq):
                                a,b,c,d = child[4*j:4*j+4]
                                want += weight*lane_eq[lane]*w*((lam*a+b)*d+lam*c*b)
                            value = [a+trial*(b-a) for a,b in zip(compact[lane][tail],compact[lane][tail+half])]
                            if support[tail] or support[tail+half]:
                                got += weight*lane_eq[lane]*(sum(
                                    (d*x*x for (d,_),x in zip(spec['features'],value)),zero)-baseline[lane])
                    assert got == want
            # Replay at the completed cell point restores even discarded directions.
            for lane,spec in enumerate(specs):
                histogram = [zero]*n
                mass = zero
                for active,b,w in zip(live,bytes_by_lane[lane],eq_table(challenges)):
                    if active:
                        histogram[b] += w
                        mass += w
                histogram[0] += one-mass
                restored = contraction.restore_children(histogram,spec['children'])
                assert restored == folded(original[lane],challenges)[0]
                assert len(spec['features']) <= spec['width']
    assert contraction.rank_bounds() == [4,8,16,17,9,5,3,2]
    assert sum(contraction.rank_bounds()) == 64


def test_contracted_byte_states_coexist_with_original_cache_and_full_arena(tmp_path):
    import subprocess
    import c71_arena_plan as arena
    report = arena.report(ordered_getter=True, reuse_reader_for_commit=True,
                          exp30_bmma=True, byte_node_contraction=True)
    binary = tmp_path/'arena'
    subprocess.run(['c++','-std=c++17','-O2','-Wall','-Wextra','-Werror',
                    'cuda/c71_arena_preflight.cpp','-o',str(binary)],check=True,timeout=60)
    for case in report['cases']:
        assert case['all_chain_layouts_fit_margin']
        p = case['address_layouts']['EXP30_maximum_original_bytes']
        assert p['fits_with_operational_margin'] and not p['device_allocation_measured']
        ids, lines = {}, []
        def index(k):
            if k.startswith(('EXP30_BMMA_layer_', 'EXP30_byte_contract_')):
                # Layer handles are reused only after all consumers release.
                k = ('BMMA:' if k.startswith('EXP30_BMMA') else 'byte:')+k.split(':',1)[1]
            if k not in ids: ids[k] = len(ids)
            return ids[k]
        for k,offset,size in p['initial_allocations']:
            lines.append(f'A {index(k)} {offset} {size}')
        live = set(k for k,_,_ in p['initial_allocations'])
        for event in p['events']:
            if event['event'].startswith('EXP30_byte_contract_'):
                assert {'EXP30:ratio_original_cache','EXP30:byte_LUT'} <= live
            for k in event['free']:
                lines.append(f'F {index(k)} 1 0'); live.remove(k)
            for k,offset,size in event['allocate']:
                lines.append(f'A {index(k)} {offset} {size}'); live.add(k)
        result = subprocess.run([str(binary)],input='\n'.join(lines)+'\n',text=True,
                                capture_output=True,check=True,timeout=10)
        assert int(result.stdout.split()[0]) == p['address_high_water_bytes']

"""Private scalar byte-tree replacement: public node-axis contraction oracle.

No FS, MAC, byte source, GPU, or hardware rate is owned by this module.
"""


def polynomial_product(a, b):
    out = [a[0]*0]*(len(a)+len(b)-1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] += x*y
    return out


def polynomial_sum(a, b):
    out = [a[0]*0]*max(len(a), len(b))
    for i, x in enumerate(a): out[i] += x
    for i, x in enumerate(b): out[i] += x
    return out


def evaluate(poly, x):
    value = poly[0]*0
    for c in reversed(poly): value = value*x+c
    return value


def byte_tree(coefficients):
    """Exactly P_left*Q_right + P_right*Q_left, Q_left*Q_right."""
    n = len(coefficients)
    if n < 2 or n & (n-1): raise ValueError('power-of-two byte alphabet required')
    zero = coefficients[0]*0
    tree = [None]*(2*n-1)
    for j, c in enumerate(coefficients): tree[n-1+j] = ([c], [zero-j, zero+1])
    for j in reversed(range(n-1)):
        p, q = tree[2*j+1]; r, s = tree[2*j+2]
        tree[j] = (polynomial_sum(polynomial_product(p,s), polynomial_product(r,q)),
                   polynomial_product(q,s))
    return tree


def diagonalize(matrix, inverse):
    """Symmetric rank-one elimination, including zero diagonal/off-diagonal pivots.

    M = sum d*v*v^T, without square roots or nonsingularity assumptions.
    The matrix and every pivot depend only on already known public data.
    """
    m = [row[:] for row in matrix]
    n = len(m); factors = []
    while True:
        pivot = next((i for i in range(n) if m[i][i] != 0), None)
        if pivot is not None:
            d, row = m[pivot][pivot], m[pivot][:]
        else:
            pair = next(((i,j) for i in range(n) for j in range(i+1,n) if m[i][j] != 0), None)
            if pair is None: return factors
            i, j = pair
            d, row = 2*m[i][j], [a+b for a,b in zip(m[i],m[j])]
        reciprocal = inverse(d)
        v = [x*reciprocal for x in row]
        factors.append((d,v))
        for i in range(n):
            for j in range(n): m[i][j] -= d*v[i]*v[j]
        if len(factors) > n: raise AssertionError('rank failed to decrease')


def contract(coefficients, layer, node_eq, lam, inverse):
    """Cell rounds only. Lane and original node rounds must still be completed."""
    n = len(coefficients); nodes = 1 << layer
    if nodes > n//2 or len(node_eq) != nodes: raise ValueError('node geometry')
    tree = byte_tree(coefficients)
    children = [tree[2*nodes-1+2*j+k][c]
                for j in range(nodes) for k in range(2) for c in range(2)]
    degree = n//(2*nodes)
    width = min(4*nodes, degree+1)
    zero = coefficients[0]*0
    if width == 4*nodes:
        basis = children
        vectors = [[zero+int(i==j) for j in range(width)] for i in range(width)]
    else:
        basis = [[zero]*i+[zero+1] for i in range(width)]
        vectors = [p+[zero]*(width-len(p)) for p in children]
    matrix = [[zero]*width for _ in range(width)]
    for j, weight in enumerate(node_eq):
        # λ*A*D + λ*C*B + B*D, with the ORIGINAL node selector contracted.
        for x,y,w in ((0,3,lam),(2,1,lam),(1,3,zero+1)):
            a,b = vectors[4*j+x], vectors[4*j+y]
            for i in range(width):
                for k in range(width): matrix[i][k] += weight*w*a[i]*b[k]
    half = inverse(zero+2)
    matrix = [[(matrix[i][j]+matrix[j][i])*half for j in range(width)] for i in range(width)]
    factors = diagonalize(matrix, inverse)
    features = []
    for d,v in factors:
        poly = [zero]*(max(map(len,basis)))
        for weight,p in zip(v,basis):
            for i,c in enumerate(p): poly[i] += weight*c
        features.append((d,[evaluate(poly,zero+b) for b in range(n)]))
    return dict(features=features, matrix=matrix, basis=basis,
                children=children, width=width, degree=degree)


def restore_children(histogram, children):
    """Recover ORIGINAL child claims, including directions discarded by the form.

    Histogram weights are Eq of the completed cell challenges. This needs a
    fresh original-byte pass; it cannot be replaced by retained diagonal values.
    """
    zero = histogram[0]*0
    return [sum((w*evaluate(p,zero+b) for b,w in enumerate(histogram)),zero) for p in children]


def rank_bounds(alphabet_bits=8):
    return [min(4*(1<<h),(1 << (alphabet_bits-1-h))+1) for h in range(alphabet_bits)]


def arena_events(case):
    """Serial candidate plan; original cache/LUT and outer slots stay live.

    Two distinct feature states coexist until a completion fence. These are
    requested payloads, not evidence for an implemented CUDA allocator.
    """
    support = [r['supported_pairs'] for r in case['rounds']]
    events = []
    for h, rank in enumerate(rank_bounds()):
        name = f'EXP30_byte_contract_{h}'
        def alloc(phase, buffers):
            events.append(dict(event=name+'_'+phase,
                allocate={name+':'+k:v for k,v in buffers.items()}))
        def free(phase, *buffers):
            events.append(dict(event=name+'_'+phase+'_fence',
                free=[name+':'+k for k in buffers]))
        alloc('public_transform', dict(public_scratch=1<<20,
            features=12*rank*256*24, diagonal=12*rank*24,
            support_spans=16*max(r['support_span_count'] for r in case['rounds'])))
        events[-1]['unknown'] = ['planned public scratch and ordered CUDA getter, not native allocation measurements']
        free('public_transform_consumed', 'public_scratch')
        alloc('nine_streaming_rounds_and_checkpoint', dict(
            scaled_LUT=(1<<9)*rank*256*24,
            pair_batch=2*rank*16384*24, pair_index_and_Eq=16384*28,
            state_0=12*rank*24*support[8]))
        free('checkpoint_complete', 'scaled_LUT', 'pair_batch', 'pair_index_and_Eq', 'features')
        for r, n in enumerate(support[9:], 1):
            alloc(f'fold_{r}_disjoint_destination', {f'state_{r%2}':12*rank*24*n})
            free(f'fold_{r}_last_source_consumer', f'state_{(r-1)%2}')
        free('cell_rounds_complete', f'state_{(len(support)-9)%2}', 'diagonal', 'support_spans')
        alloc('original_child_recovery', dict(histogram=16*256*36,
            original_children=16*(1<<h)*4*24))
        free('histogram_last_consumer', 'histogram')
        # Lane/node folding also keeps source and destination disjoint.
        alloc('original_lane_node_fold', dict(child_destination=16*(1<<h)*2*24))
        free('original_endpoint', 'original_children', 'child_destination')
    return events


def report():
    """Construction screen, not a native trace or a hardware lower/upper."""
    import c71_gkr_screen as gkr
    ranks = rank_bounds()
    cases = []
    checkpoint = 9
    for c in gkr.ratio_cases():
        support = [r['supported_pairs'] for r in c['rounds']]
        # Twelve original byte lanes; four lanes and all structural padding
        # are the public zero-byte baseline, not discarded constraints.
        states = [12*max(ranks)*24*n for n in support[checkpoint-1:]]
        # Two disjoint allocations until a fence: compacted support is NOT
        # assumed to permit an in-place fold or to halve on every round.
        state_peak = max(a+b for a,b in zip(states,states[1:]+[0]))
        cases.append(dict(old_tokens=c['old_tokens'], canonical_rank_upper_per_layer=ranks,
            full_original_coefficient_pairs=255*c['padded_cells']*16-8,
            supported_cell_pairs=sum(support),
            supported_pair_diagonal_coefficient_Fp3_products_upper=
                12*sum(support)*sum(5*r+6 for r in ranks),
            scalar_lane_node_tail_Fp3_products=18*sum(16*(1<<h)-1 for h in range(8)),
            retained_features_after_nine_cell_rounds_bytes=states[0],
            disjoint_retained_fold_payload_peak_bytes=state_peak,
            per_lane_scaled_feature_LUT_peak_bytes=(1<<checkpoint)*256*max(ranks)*24,
            scaled_feature_LUT_Fp3_products_upper=((1<<(checkpoint+1))-1)*256*12*sum(ranks),
            cached_original_byte_reads_for_regeneration_checkpoint_recovery_upper=
                (checkpoint+2)*8*12*c['live_cells'],
            early_feature_regeneration_Fp3_additions_upper=(checkpoint+1)*12*c['live_cells']*sum(ranks),
            retained_feature_fold_Fp3_products_upper=12*sum(ranks)*sum(support[checkpoint:]),
            recovery_wide_histogram_bytes=16*256*36,
            recovered_original_children_payload_peak_bytes=16*128*4*24,
            recovery_node_contractions_Fp3_products=16*256*4*255,
            public_support_zero_baseline_required=True,
            checkpoint_liveness_is_component_only=True))
    return dict(credit=False, scope='node-axis contraction, same original cubic and child claims',
        cases=cases, rank_sum_upper=sum(ranks), original_child_functions=4*255,
        asymptotic_cell_work='O(N*sqrt(B)) versus O(N*B) for byte alphabet B, public transforms and terminal replay separate',
        complete_work=False, complete_peak=False, complete_time=False,
        missing=['native original-field/transcript/MAC refinement',
                 'public transforms, baseline coefficients, Eq and full instruction/traffic counts',
                 'scaled-LUT streaming and compact support getters',
                 'joint allocator/fences/peak and measured service rates'],
        spending_gate='NO-GO for spending; algebra and component payload bounds only')


if __name__ == '__main__':
    import json
    print(json.dumps(report(),indent=2))

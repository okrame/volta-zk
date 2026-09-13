"""Finite algebra for two concrete streaming schedules; no native prover credit."""
import hashlib
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_streaming_screen as screen


def test_integrated_screen_counts_old_A_and_does_not_invent_a_time_upper():
    r = screen.integrated_resource_ledger(screen.base.b12_pcs_binding_assessment())
    cases = r['cases']
    assert [c['initial_oracle_A_visits_by_generation'] for c in cases] == [
        [1024], [512, 1024], [512, 512, 1024]]
    assert cases[1]['initial_oracle_bandwidth_lower_seconds_conditional'] > 50
    assert all(c['initial_oracle_plus_generic_merge_lower_seconds_conditional'] > 50
               and c['complete_seconds_upper'] is None for c in cases)
    assert r['time_upper_contract']['admission_upper'] == '+infinity'
    assert r['memory']['W_KV_arena_known_reserved_bytes'] == 70_048_981_504
    assert r['data_oracles']['35'][1]['encoded_bytes'] == 103_079_215_104
    assert r['data_oracles']['34'][1]['encoded_bytes'] == 51_539_607_552
    variant = r['query_remainder_range_variant']
    assert variant['range_W_visits_with_cached_histogram'] == 29


def table(factors, p):
    out = [1]
    for a, b in factors:
        out = [x*y % p for x in out for y in (a, b)]
    return out


def fold(values, r, p):
    h = len(values)//2
    return [(a+r*(b-a)) % p for a, b in zip(values[:h], values[h:])]


def coefficients(a, b, p):
    h = len(a)//2
    c = [0, 0, 0]
    for a0, a1, b0, b1 in zip(a[:h], a[h:], b[:h], b[h:]):
        da, db = a1-a0, b1-b0
        c[0] += a0*b0
        c[1] += a0*db+da*b0
        c[2] += da*db
    return [x % p for x in c]


def challenge(transcript, c, p):
    transcript.append(c)
    return int.from_bytes(hashlib.sha256(repr(transcript).encode()).digest(), 'big') % p


def two_pass(source, factors, k, p):
    """Reference algebra only: pass 1 explicitly pays rank*N contractions."""
    d = len(factors[0])
    suffix = 1 << (d-k)
    u = [table(f[:k], p) for f in factors]
    v = [table(f[k:], p) for f in factors]
    a = [[0]*(1 << k) for _ in factors]
    for index, value in source():
        i, j = divmod(index, suffix)
        for row, weight in zip(a, v):
            row[i] = (row[i]+value*weight[j]) % p
    transcript, point = [], []
    for _ in range(k):
        cs = [coefficients(x, y, p) for x, y in zip(a, u)]
        c = [sum(x[t] for x in cs) % p for t in range(3)]
        r = challenge(transcript, c, p)
        point.append(r)
        a, u = ([fold(x, r, p) for x in rows] for rows in (a, u))
    prefix_weights = table([(1-r, r) for r in point], p)
    b = [0]*suffix
    for index, value in source():
        i, j = divmod(index, suffix)
        b[j] = (b[j]+prefix_weights[i]*value) % p
    public = [sum(x[0]*y[j] for x, y in zip(u, v)) % p for j in range(suffix)]
    for _ in range(d-k):
        c = coefficients(b, public, p)
        r = challenge(transcript, c, p)
        point.append(r)
        b, public = fold(b, r, p), fold(public, r, p)
    return transcript, point, b[0], public[0]


def test_two_pass_matches_dense_and_support_pruning_is_unsound():
    p = 97
    for d, k in ((2, 1), (5, 2), (6, 3)):
        values = [(i*i+7*i+11) % p for i in range(1 << d)]
        factors = [[(1-z, z) for z in [(r+3*j) % p for j in range(d)]]
                   for r in (0, 1, 7)]
        # Fixed prefix selectors include disjoint aligned cubes.
        factors[0][0], factors[1][0] = (1, 0), (0, 1)
        scans = []
        def source():
            scans.append(0)
            for item in enumerate(values):
                scans[-1] += 1
                yield item
        actual = two_pass(source, factors, k, p)
        a = values[:]
        b = [sum(xs) % p for xs in zip(*(table(f, p) for f in factors))]
        transcript, point = [], []
        for _ in range(d):
            r = challenge(transcript, coefficients(a, b, p), p)
            point.append(r)
            a, b = fold(a, r, p), fold(b, r, p)
        assert actual == (transcript, point, a[0], b[0])
        assert scans == [1 << d, 1 << d]
    # W(x,y)=x*(1-y), L(x,y)=(1-x)*(1-y). Boolean target is zero,
    # but the first sumcheck polynomial is x-x^2. Dropping A(1), just
    # because the original cube has prefix zero, wrongly sends all zeros.
    assert coefficients([0, 0, 1, 0], [1, 0, 0, 0], p) == [0, 1, p-1]
    assert coefficients([0, 0], [1, 0], p) == [0, 0, 0]


def test_coset_encoding_is_exact_but_replays_full_coefficients():
    p, height, size = 97, 32, 4
    g = pow(5, (p-1)//height, p)
    coeffs = [2, 7, 11, 13, 17, 23, 29, 31, 37, 41]
    values = {}
    for coset in range(height//size):
        z = pow(g, coset, p)
        reduced = [0]*size
        for i, a in enumerate(coeffs):
            reduced[i % size] = (reduced[i % size]+a*pow(z, i, p)) % p
        for j in range(size):
            y = pow(g, (height//size)*j, p)
            index = coset+(height//size)*j
            values[index] = sum(a*pow(y, i, p) for i, a in enumerate(reduced)) % p
    assert values == {j: sum(a*pow(g, j*i, p) for i, a in enumerate(coeffs)) % p
                      for j in range(height)}
    r = screen.report()
    assert [x['body_wire_interval'][0] for x in r['wire']] == [47841180, 54868318, 61797384]
    assert r['wire'][0]['known_primitives_plus_body_interval'] == [109682470, 126894534]
    assert r['canonical_required_base_rows'] == 11466948 < r['Dory_base_capacity']
    by_d = {x['dimension']: x for x in r['coset_replay']}
    assert by_d[35]['full_source_scans_lower'] == 683
    assert by_d[34]['full_source_scans_lower'] == 342
    assert by_d[35]['buffer_bytes_needed_for_four_scans_lower'] == 1 << 40
    assert by_d[34]['buffer_bytes_needed_for_four_scans_lower'] == 1 << 39
    assert all(Fraction(x) < Fraction(1, 1 << 78)
               for x in r['conditional_B12_plus_bootstrap_union'].values())
    assert not r['goal_complete'] and not r['physical_schedule_admitted']
    suffix = r['suffix_first_W_linear_reducer']
    assert suffix['cube_count'] == 3622
    assert suffix['named_arrays_simultaneous_bytes'] == 2898788352 < r['arena_bytes']
    assert suffix['first_scan_update_model'] == 280138842112
    assert suffix['both_scans_update_model'] == 314498580480
    assert not suffix['includes_PCS_range_witness_or_runtime']


def test_suffix_first_restores_the_original_PCS_endpoint():
    p, d, suffix_bits = 97, 6, 2
    values = [(11*i+i*i+3) % p for i in range(1 << d)]
    # Two aligned cubes: prefix selectors stay in the contracted half.
    factors = [[(1, 0), (0, 1), (1, 0), (1-7, 7), (1-11, 11), (1-19, 19)],
               [(0, 1), (1, 0), (1, 0), (1-13, 13), (1-17, 17), (1-23, 23)]]
    reordered = [f[-suffix_bits:]+f[:-suffix_bits] for f in factors]
    scans = []
    def source():
        scans.append(0)
        for index, value in enumerate(values):
            prefix, suffix = divmod(index, 1 << suffix_bits)
            scans[-1] += 1
            yield (suffix << (d-suffix_bits))+prefix, value
    _, new_point, value, public = two_pass(source, reordered, suffix_bits, p)
    original_point = new_point[suffix_bits:]+new_point[:suffix_bits]
    eq = table([(1-r, r) for r in original_point], p)
    original_L = [sum(xs) % p for xs in zip(*(table(f, p) for f in factors))]
    assert value == sum(x*w for x, w in zip(values, eq)) % p
    assert public == sum(x*w for x, w in zip(original_L, eq)) % p
    assert scans == [1 << d, 1 << d]


def test_range_checkpoint_roots_and_integrated_liveness_screen():
    p, d = 97, 7
    leaves = [(1, (83-i*i) % p) for i in range(1 << d)]
    def tree(level):
        levels = [level]
        while len(levels[-1]) > 1:
            row = levels[-1]
            levels.append([((a*d+b*c) % p, b*d % p)
                           for (a, b), (c, d) in zip(row[::2], row[1::2])])
        return levels
    reference = tree(leaves)
    for cut in (2, 3, 4):
        block = 1 << cut
        # Only one small subtree is live while computing each checkpoint.
        roots = [tree(leaves[i:i+block])[-1][0] for i in range(0, len(leaves), block)]
        assert tree(roots) == reference[cut:]

    suffix = screen.suffix_first_weight_budget()
    r = screen.integrated_schedule_screen(suffix)
    assert r['old_simultaneous_arrays_margin'] == 3543662592
    assert r['HBM_after_W_and_full_arena_before_other_residents'] == 12162858496
    assert [p['named_arrays_bytes'] for p in r['phase_liveness']] == [2848456704, 50331648]
    assert r['full_range_source_visible_core_peak'] == 6184752906192
    assert r['private_global_W_histogram_u64_bytes'] == 524280
    checkpoints = r['checkpoint_top_only']
    assert [c['named_peak_with_C_bytes'] for c in checkpoints] == [5234491344, 5465702352]
    assert all(c['named_peak_with_C_bytes'] < r['arena_bytes'] for c in checkpoints)
    assert [c['partial_W_scans_lower_with_cached_histogram'] for c in checkpoints] == [14, 15]
    assert screen.range_checkpoint_budget(35, 10, suffix['contraction_bytes'])['named_peak_with_C_bytes'] > r['arena_bytes']
    assert r['complete_W_scans_upper'] is None and r['complete_seconds_upper'] is None
    assert not r['admitted']


def test_checkpoint_replay_then_retain_matches_adaptive_dense_rounds():
    p, d, retained_bits = 97, 7, 3
    values = [(i*i+3*i+7) % 71 for i in range(1 << d)]
    def merge(a, b):
        return ((a[0]*b[1]+b[0]*a[1]) % p, a[1]*b[1] % p)
    full = [[(1, (89-w) % p) for w in values]]
    while len(full[-1]) > 1:
        row = full[-1]
        full.append([merge(a, b) for a, b in zip(row[::2], row[1::2])])

    def cubic(a, b, ea, eb):
        v = [0, 0, 0]
        for x, y, lam in ((0, 3, 13), (2, 1, 13), (1, 3, 1)):
            dx, dy = b[x]-a[x], b[y]-a[y]
            for j, z in enumerate((a[x]*a[y], dx*a[y]+a[x]*dy, dx*dy)):
                v[j] += lam*z
        c = [0]*4
        for j in range(3):
            c[j] += ea*v[j]
            c[j+1] += (eb-ea)*v[j]
        return [x % p for x in c]

    def prefixes(point, index=0, weight=1, depth=0):
        if depth == len(point):
            yield index, weight
        else:
            yield from prefixes(point, 2*index, weight*(1-point[depth]) % p, depth+1)
            yield from prefixes(point, 2*index+1, weight*point[depth] % p, depth+1)

    for m in range(4, d):
        height = d-m-1
        level = full[height]
        dense = [[level[2*i+j//2][j % 2] for i in range(1 << m)] for j in range(4)]
        equality = table([(1-r, r) for r in range(2, m+2)], p)
        prefix, transcript, scans = [], [], []
        visits = [0, 0]
        def root(start, h):
            if not h:
                visits[0] += 1
                return 1, (89-values[start]) % p
            a, b = root(start, h-1), root(start+(1 << (h-1)), h-1)
            visits[1] += 1
            return merge(a, b)
        def gathered(suffix):
            out = [0]*4
            for high, weight in prefixes(prefix):
                index = (high << (m-len(prefix)))+suffix
                pair = (*root((2*index) << height, height),
                        *root((2*index+1) << height, height))
                for j in range(4):
                    out[j] = (out[j]+weight*pair[j]) % p
            return out
        resident = None
        for round_index in range(m):
            size, half = len(equality), len(equality)//2
            visits[:] = [0, 0]
            if resident is None and m-round_index <= retained_bits:
                resident = list(map(list, zip(*(gathered(i) for i in range(size)))))
                assert resident == dense
            actual, expected = [0]*4, [0]*4
            for i in range(half):
                a, b = ([row[i] for row in dense], [row[i+half] for row in dense])
                ga, gb = ((gathered(i), gathered(i+half)) if resident is None else
                          ([row[i] for row in resident], [row[i+half] for row in resident]))
                for j, (x, y) in enumerate(zip(cubic(a, b, equality[i], equality[i+half]),
                                              cubic(ga, gb, equality[i], equality[i+half]))):
                    expected[j] = (expected[j]+x) % p
                    actual[j] = (actual[j]+y) % p
            assert actual == expected
            if visits[0]:
                assert visits == [1 << d, (1 << d)-(1 << (m+1))]
                scans.append(visits[:])
            r = challenge(transcript, actual, p)
            prefix.append(r)
            dense = [fold(row, r, p) for row in dense]
            if resident is not None:
                resident = [fold(row, r, p) for row in resident]
            equality = fold(equality, r, p)
        assert resident == dense
        assert len(scans) == 1+max(0, m-retained_bits)
    r = screen.checkpoint_round_replay_budget(35, 10, 61394690560, 25)
    assert r['range_W_visits_with_cached_histogram'] == 56
    assert r['retained_children_and_eq_bytes'] == 4026531840 < 6442450944
    assert r['external_W_bytes_if_resident'] == 0
    assert r['runtime_upper'] is None and not r['rejected_for_read_count']


def test_gram_windows_preserve_cubic_messages_and_original_terminal():
    p, d, lam = 97, 7, 13
    rows = [[(7*i*i+(j+3)*i+11*j+2) % p for i in range(1 << d)] for j in range(4)]
    parent = [2, 5, 11, 17, 23, 31, 41]
    equality = table([(1-r, r) for r in parent], p)
    original = [row[:] for row in rows]
    point, transcript = [], []
    def cubic_dense(children, weights):
        h = len(weights)//2
        out = [0]*4
        for i in range(h):
            v = [0]*3
            for x, y, scale in ((0, 3, lam), (2, 1, lam), (1, 3, 1)):
                a, b = children[x][i], children[y][i]
                da, db = children[x][i+h]-a, children[y][i+h]-b
                for j, c in enumerate((a*b, da*b+a*db, da*db)):
                    v[j] += scale*c
            for j in range(3):
                out[j] += weights[i]*v[j]
                out[j+1] += (weights[i+h]-weights[i])*v[j]
        return [x % p for x in out]
    for width in (3, 2, 2):
        before = len(point)
        length, tail = 1 << width, len(rows[0]) >> width
        tail_eq = table([(1-r, r) for r in parent[before+width:]], p)
        H = [[0]*length for _ in range(length)]
        for t in range(tail):
            for u in range(length):
                a, b, c, _ = [row[u*tail+t] for row in rows]
                U, V = tail_eq[t]*(lam*a+b), tail_eq[t]*lam*c
                for v in range(length):
                    H[u][v] = (H[u][v]+U*rows[3][v*tail+t]+V*rows[1][v*tail+t]) % p
        for step in range(width):
            h = len(H)//2
            tail_weights = table([(1-r, r) for r in parent[before+step+1:before+width]], p)
            prefix_weight = 1
            for x, r in zip(parent, point):
                prefix_weight = prefix_weight*((1-x)*(1-r)+x*r) % p
            v = [0, 0, 0]
            for z, w in enumerate(tail_weights):
                a, b, c, e = H[z][z], H[z][z+h], H[z+h][z], H[z+h][z+h]
                for j, val in enumerate((a, b+c-2*a, e-b-c+a)):
                    v[j] += w*val
            x = parent[len(point)]
            coeff = [0]*4
            for j in range(3):
                coeff[j] += prefix_weight*(1-x)*v[j]
                coeff[j+1] += prefix_weight*(2*x-1)*v[j]
            coeff = [c % p for c in coeff]
            assert coeff == cubic_dense(rows, equality)
            r = challenge(transcript, coeff, p)
            point.append(r)
            H = [[((1-r)**2*H[i][j]+r*(1-r)*(H[i+h][j]+H[i][j+h])+r*r*H[i+h][j+h]) % p
                  for j in range(h)] for i in range(h)]
            rows = [fold(row, r, p) for row in rows]
            equality = fold(equality, r, p)
    eq = table([(1-r, r) for r in point], p)
    assert [r[0] for r in rows] == [sum(a*b for a, b in zip(row, eq)) % p for row in original]
    budget = screen.gram_window_budget(35, 10, 61394690560, 25)
    assert [x['window_bits'] for x in budget['layers']] == [
        [], [1], [2], [3], [4], [5], [2, 4], [3, 4], [2, 2, 4], [2, 3, 4]]
    assert budget['range_W_visits_with_cached_histogram'] == 26
    assert budget['fraction_merges_initial_and_replay'] == 640151453695
    assert budget['comparable_core_Fp3_mul_expressions'] == 3146566859825
    assert budget['H_scalar_interpolations'] == 2565
    assert budget['largest_H_bytes'] == 24576
    assert budget['runtime_upper'] is None and not budget['credit']


def test_coset_emission_merkle_frontier_and_queried_path_match_dense():
    def frame_hash(domain, *parts):
        h = hashlib.sha256()
        h.update(len(domain).to_bytes(4, 'little'))
        h.update(domain)
        for part in parts:
            h.update(len(part).to_bytes(8, 'little'))
            h.update(part)
        return h.digest()

    def stream_bytes(seed, offset, length):
        out = bytearray()
        while len(out) < length:
            block, within = divmod(offset, 32)
            chunk = frame_hash(b'toy-xof', seed, block.to_bytes(8, 'little'))
            take = min(length-len(out), 32-within)
            out.extend(chunk[within:within+take])
            offset += take
        return bytes(out)

    def sample_salt(seed, offset, prime=241):
        salt = []
        while len(salt) < 4:
            value = stream_bytes(seed, offset, 1)[0]
            offset += 1
            if value < prime:
                salt.append(value)
        return bytes(salt), offset

    def leaf(index, salt):
        # Toy seekable rejection stream only: not native PrivateRng or its refinement.
        return frame_hash(b'leaf', index.to_bytes(8, 'little'), salt,
                          (index*index+17).to_bytes(8, 'little'))

    def parent(left, right):
        return frame_hash(b'node', left, right)

    def canonical_salts(height, cosets):
        seed, offset, salts, starts = b'seed', 0, [], []
        for index in range(height):
            if index % cosets == 0:
                starts.append(offset)
            salt, offset = sample_salt(seed, offset)
            salts.append(salt)
        return seed, salts, starts, offset

    def dense_direct(salts):
        level = [leaf(i, salt) for i, salt in enumerate(salts)]
        levels = [level]
        while len(level) > 1:
            level = [parent(level[i], level[i+1]) for i in range(0, len(level), 2)]
            levels.append(level)
        return levels

    def emit(height, cosets, seed, starts, expected_salts, query=None):
        length = height//cosets
        frontiers = [[] for _ in range(length)]
        offsets = starts[:]
        upper, path, maximum = [], [], 0

        def push(stack, node, base=1):
            digest, start, size = node
            level = (size//base).bit_length()-1
            while level < len(stack) and stack[level] is not None:
                left = stack[level]
                if query is not None and (left[1] <= query < left[1]+left[2]
                                          or start <= query < start+size):
                    path.append(digest if left[1] <= query < left[1]+left[2] else left[0])
                digest, start, size = parent(left[0], digest), left[1], 2*size
                stack[level] = None
                level += 1
            if level == len(stack):
                stack.append((digest, start, size))
            else:
                stack[level] = (digest, start, size)

        for c in range(cosets):
            for j in range(length):
                index = c+cosets*j
                salt, offsets[j] = sample_salt(seed, offsets[j])
                assert salt == expected_salts[index]
                push(frontiers[j], (leaf(index, salt), index, 1))
                if c+1 == cosets:
                    push(upper, next(node for node in frontiers[j] if node is not None), cosets)
                    frontiers[j].clear()
            maximum = max(maximum, sum(node is not None for stack in frontiers for node in stack)
                          + sum(node is not None for node in upper))
        root = next(node[0] for node in upper if node is not None)
        return root, path, maximum

    def verify(index, digest, path, root):
        for sibling in path:
            digest = parent(sibling, digest) if index & 1 else parent(digest, sibling)
            index >>= 1
        return digest == root

    for height, cosets in ((32, 4), (32, 8), (64, 4), (64, 8)):
        seed, salts, starts, final_offset = canonical_salts(height, cosets)
        assert final_offset > 4*height  # The toy prime exercises rejection.
        levels = dense_direct(salts)
        for query in (0, height//3, height-1):
            root, path, maximum = emit(height, cosets, seed, starts, salts, query)
            expected_path = [level[(query >> level_index) ^ 1]
                             for level_index, level in enumerate(levels[:-1])]
            assert root == levels[-1][0]
            assert path == expected_path
            assert verify(query, leaf(query, salts[query]), path, root)
            assert maximum <= max(n.bit_count() for n in range(1, cosets+1))*(height//cosets) \
                + (height//cosets).bit_length()
            damaged = bytearray(path[0])
            damaged[0] ^= 1
            assert not verify(query, leaf(query, salts[query]), [bytes(damaged), *path[1:]], root)
            assert not verify(query, leaf(query, salts[query]), path, bytes(32))


def test_square_fused_fft_schedule_preserves_natural_order():
    p = screen.base.P

    def transpose(values, width):
        return [values[b+width*a] for b in range(width) for a in range(width)]

    def row_ffts(values, width):
        return sum((screen.base.small_goldilocks_fft(values[i:i+width])
                    for i in range(0, len(values), width)), [])

    for width in (4, 8, 16):
        size = width*width
        omega = pow(7, (p-1)//size, p)
        values = [(13*i*i+7*i+19) % p for i in range(size)]
        work = row_ffts(transpose(values, width), width)
        for a in range(width):
            for u in range(width):
                work[u+width*a] = work[u+width*a]*pow(omega, a*u, p) % p
        work = transpose(work, width)
        work = transpose(row_ffts(work, width), width)
        assert work == screen.base.small_goldilocks_fft(values)

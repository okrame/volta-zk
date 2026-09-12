"""Finite check of Dory's acceptance-set seam, not a PCG security test."""
from itertools import product


def block_keys(puncture, last_left_sum):
    """Two-level modified key vector (Dory (8)–(10)), K=F5, offset=1.

    H(x)=3*x+1 has Half-Tree's form for sigma(x)=2*x, pi(x)=3*x+1.
    The first left sum is 0; the honest second left sum is H(0)+H(1)=0.
    The verifier can instead supply a different second sum before U.
    """
    nodes = {}
    for depth, left_sum in enumerate((0, last_left_sum)):
        if depth:
            nodes = {child: value for i, x in nodes.items()
                     for child, value in ((2*i, (3*x+1) % 5),
                                          (2*i+1, (x-(3*x+1)) % 5))}
        sibling = (puncture >> (1-depth)) ^ 1
        side = sibling & 1
        total = left_sum if side == 0 else 1-left_sum
        nodes[sibling] = (total-sum(x for j, x in nodes.items() if j & 1 == side)) % 5
    nodes[puncture] = (1-sum(nodes.values())) % 5
    return tuple(nodes[i] for i in range(4))


def test_joint_check_can_be_noncartesian_and_split_checks_fix_the_seam():
    honest = [block_keys(a, 0) for a in range(4)]
    assert honest == [(1, 4, 4, 2)] * 4
    keys = [block_keys(a, 1) for a in range(4)]
    assert keys == [(2, 3, 4, 2)] * 2 + [(1, 4, 0, 1)] * 2
    assert all(sum(k) % 5 == 1 for k in keys)
    paths = set(product(range(4), repeat=2))
    # A possible public linear hash: first leaf of block 0 minus block 1.
    accepted = {(a, b) for a, b in paths if (keys[a][0]-keys[b][0]) % 5 == 0}
    assert len(accepted) == 8 and (0, 0) in accepted and (2, 2) in accepted
    assert (0, 2) not in accepted
    projections = [{x[i] for x in accepted} for i in range(2)]
    assert set(product(*projections)) == paths != accepted

    # Enumerate ALL F5^4 linear hashes on the block vectors. A collision of
    # the two distinct key vectors occurs for exactly 1/5 of these hashes.
    collisions = 0
    for coefficients in product(range(5), repeat=4):
        hashes = [sum(c*x for c, x in zip(coefficients, k)) % 5 for k in keys]
        collisions += hashes[0] == hashes[2]
        for target in range(5):
            kept = {a for a in range(4) if hashes[a] == target}
            if hashes[0] != hashes[2]:
                assert len({keys[a] for a in kept}) <= 1
    assert collisions == 5**3
    # Separate checks with only one final AND expose a Cartesian predicate.
    first = {a for a in range(4) if keys[a][0] == 2}
    second = {b for b in range(4) if keys[b][0] == 1}
    assert set(product(first, second)) == {(0, 2), (0, 3), (1, 2), (1, 3)}

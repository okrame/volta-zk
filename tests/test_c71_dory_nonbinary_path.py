"""Finite algebra for Dory Fig. 5; neither a PCG implementation nor a bound."""
from itertools import permutations, product


def setup(pi, beta, delta, last_r, c0=2):
    """Honest two-level sender, valid base MACs, receiver path r=(0,last_r).

    K=F5 is only the finite example. H(x)=pi(2*x)+2*x and sigma=2*id.
    Return the receiver's view separately from the honest sender's leaves.
    """
    h = lambda x: (pi[2*x % 5] + 2*x) % 5
    values, tags = (beta, 3, 4), (1, 2, 3)
    keys = tuple((m-x*delta) % 5 for x, m in zip(values, tags))
    r = (0, last_r)
    d = tuple((values[j+1]-r[j]*beta) % 5 for j in range(2))
    mr = tuple((r[j]*tags[0]-tags[j+1]) % 5 for j in range(2))
    kr = tuple((-keys[j+1]-d[j]*delta) % 5 for j in range(2))
    assert all((mr[j]-kr[j]-r[j]*keys[0]) % 5 == 0 for j in range(2))
    left_root = (c0-kr[0]) % 5
    right_root = (keys[0]-left_root) % 5
    leaves = (h(left_root), (left_root-h(left_root)) % 5,
              h(right_root), (right_root-h(right_root)) % 5)
    c1 = (kr[1]+leaves[0]+leaves[2]) % 5
    # Everything below is computed from public c, private receiver seed
    # values/tags, and forward H queries; it does not require delta.
    sibling = (c0-mr[0]) % 5
    ell = (c1-mr[1]-h(sibling)) % 5
    known = (h(sibling), (sibling-h(sibling)) % 5)
    return (beta, tags[0], sibling, ell, known), leaves


def test_nonbinary_final_choice_passes_every_linear_check():
    pi = (3, 0, 4, 1, 2)
    for delta, r in product(range(5), (2, 3, 4)):
        (beta, mb, sibling, ell, known), keys = setup(pi, 2, delta, r)
        noise = (0, 0, r*beta % 5, (1-r)*beta % 5)
        tags = (*known, (ell+r*mb) % 5, (-sibling-ell+(1-r)*mb) % 5)
        assert sum(x != 0 for x in noise) == 2  # Not a single-point noise.
        assert all((m-k-x*delta) % 5 == 0 for x, m, k in zip(noise, tags, keys))
        # These MAC identities also hold for every prefix accumulation.
        for stop in range(1, 5):
            assert (sum(tags[:stop])-sum(keys[:stop])-sum(noise[:stop])*delta) % 5 == 0
        for chi in product(range(5), repeat=4):
            dot = lambda xs: sum(c*x for c, x in zip(chi, xs)) % 5
            mask, mask_tag = 2, 4
            mask_key = (mask_tag-mask*delta) % 5
            z = (mask+dot(noise)) % 5
            w = (dot(tags)+mask_tag) % 5
            v = (dot(keys)+mask_key+z*delta) % 5
            assert w == v  # Includes a separate check for this whole block.


def test_base_field_scalar_orthomorphism_reveals_delta_with_one_inverse():
    # All 120 permutations, all honest deltas, nonzero betas and first c.
    # The receiver below uses only its view and ONE pi inverse query.
    for pi in permutations(range(5)):
        inverse = {y: x for x, y in enumerate(pi)}
        for delta, beta, c0 in product(range(5), range(1, 5), range(5)):
            (beta, mb, sibling, ell, _), _ = setup(pi, beta, delta, 2, c0)
            x = inverse[(ell+2*sibling) % 5]
            recovered_offset = (sibling+pow(2, -1, 5)*x) % 5
            recovered_delta = (mb-recovered_offset)*pow(beta, -1, 5) % 5
            assert recovered_delta == delta


def test_zero_payload_reveals_delta_before_check_for_any_hash():
    # Enumerate every H:Fp->Fp, not just invertible or affine functions.
    # This uses only forward H queries and works in characteristic two too.
    for p in (2, 5):
        for h in product(range(p), repeat=p):
            for delta, c0 in product(range(p), repeat=2):
                values, tags = (0, 1, 1), (1, 1, 1)
                keys = tuple((m-x*delta) % p for x, m in zip(values, tags))
                d = (values[1], (values[2]-1) % p)  # Last gamma=s-d=1.
                kr = tuple((-keys[j+1]-d[j]*delta) % p for j in range(2))
                left = (c0-kr[0]) % p
                right = (keys[0]-left) % p
                last_left_sum = (h[left]+h[right]) % p
                c1 = (kr[1]+last_left_sum) % p
                # Receiver: beta=0 makes offset=M(beta) known. The first
                # d was honest, so the entire tree is known from c0.
                known_left = (c0+tags[1]) % p
                known_right = (tags[0]-known_left) % p
                known_sum = (h[known_left]+h[known_right]) % p
                recovered_delta = (c1+tags[2]-known_sum) % p
                assert recovered_delta == delta

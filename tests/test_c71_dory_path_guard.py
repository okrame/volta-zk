"""Candidate pre-cGGМ path guard on original MACs, finite algebra only."""
from itertools import product


def test_path_guard_covers_binary_paths_and_zero_payload_without_inverse():
    p = 5
    # Two original s rows and one beta row; public d changes values/keys,
    # never the tags. Native k=m+Delta*x throughout this test.
    beta_m, seed_m = 4, (1, 2)
    mask_x, mask_m = 3, 4
    for beta, s0, s1, d0, d1 in product(range(p), repeat=5):
        s, d = (s0, s1), (d0, d1)
        gamma = tuple((s[j]-d[j]) % p for j in range(2))
        errors = tuple(g*(g-beta) % p for g in gamma)
        valid = not any(errors)
        if beta:
            extracted = tuple(g*pow(beta, -1, p) % p for g in gamma)
            assert valid == all(r in (0, 1) for r in extracted)
        else:
            assert valid == (s == d)
        bad_lambdas = 0
        for lam in range(p):
            error = (errors[0]+lam*errors[1]) % p
            bad_lambdas += error == 0
            a = (mask_x+sum(pow(lam, j, p)*(
                gamma[j]*(seed_m[j]-beta_m)+(gamma[j]-beta)*seed_m[j])
                for j in range(2))) % p
            b = (mask_m+sum(pow(lam, j, p)*seed_m[j]*(seed_m[j]-beta_m)
                           for j in range(2))) % p
            for delta in range(p):
                beta_k = (beta_m+delta*beta) % p
                seed_k = tuple((seed_m[j]+delta*s[j]) % p for j in range(2))
                gamma_k = tuple((seed_k[j]-delta*d[j]) % p for j in range(2))
                expected = (mask_m+delta*mask_x+sum(pow(lam, j, p)*
                    gamma_k[j]*(gamma_k[j]-beta_k) for j in range(2))) % p
                assert (expected-b-delta*a) % p == delta**2*error % p
                if valid:
                    assert expected == (b+delta*a) % p
                elif error and delta:
                    assert expected != (b+delta*a) % p
        if not valid:
            assert bad_lambdas <= 1  # A nonzero degree-one batch error.
    # The earlier last-level attacks fail the predicate BEFORE c is sent.
    assert 1*(1-0) % p != 0  # beta=0, malformed gamma_last=1.
    assert (2*1)*(2*1-1) % p != 0  # beta=1, nonbinary r_last=2.

"""Algebra of a candidate pre-correction check, not a Dory security proof."""
from itertools import product


def test_nonzero_product_check_uses_original_macs_and_one_mask():
    p = 5
    # Native signs k=m+delta*x, as in range::{prove,verify}_products.
    # The constant product 1 has tag 0 and verifier key delta.
    mask_x, mask_m = 3, 4
    for beta, eta, delta in product(range(p), repeat=3):
        beta_m, eta_m = 1, 2
        beta_k, eta_k = (beta_m+delta*beta) % p, (eta_m+delta*eta) % p
        a = (mask_x+beta*eta_m+eta*beta_m) % p
        b = (mask_m+beta_m*eta_m) % p
        expected = (mask_m+delta*mask_x+beta_k*eta_k-delta**2) % p
        assert (expected-b-delta*a) % p == delta**2*(beta*eta-1) % p
        if beta*eta % p == 1:
            assert (b+delta*a) % p == expected
        elif beta == 0 and delta != 0:
            assert (b+delta*a) % p != expected
    # A false beta=0 equation cannot become a polynomial identity in Delta
    # through any two wire changes fixed without Delta: at most two roots.
    for change_a, change_b in product(range(p), repeat=2):
        assert sum((delta**2+change_a*delta+change_b) % p == 0
                   for delta in range(p)) <= 2
    # Ordered batching leaves a nonzero error polynomial of degree <=t-1.
    for errors in product(range(p), repeat=3):
        if any(errors):
            assert sum(sum(e*pow(lam, i, p) for i, e in enumerate(errors)) % p == 0
                       for lam in range(p)) <= 2

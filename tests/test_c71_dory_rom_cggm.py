"""Finite algebra check for the guarded, domain-separated ROM cGGM."""
from itertools import product


def test_binary_hidden_query_extracts_delta_and_programs_one_oracle_point():
    p = 5
    # At an internal node u=K(beta)-w, z is the disclosed sibling.
    # Domain separation makes (block, level, position) unique, so no two
    # constraints below share an oracle entry.
    for beta, delta, m_beta, w, bit, z in product(range(1, p), range(p),
                                                  range(p), range(p),
                                                  (0, 1), range(p)):
        k_beta = (m_beta-beta*delta) % p
        hidden = (k_beta-w) % p
        guessed = (m_beta-w-hidden)*pow(beta, -1, p) % p
        required = (hidden-z) % p if bit == 0 else z
        assert guessed == delta
        left = required
        right = (hidden-required) % p
        assert (right if bit == 0 else left) == z


def test_zero_payload_branch_is_forward_simulatable_without_delta():
    p = 5
    hashes = tuple(range(p))
    for delta, m_beta, m_s0, m_s1, c0, h0, h1 in product(
            range(p), range(p), range(p), range(p), range(p), hashes, hashes):
        beta = 0
        k_beta = m_beta
        k_r = (-m_s0 % p, -m_s1 % p)  # guard acceptance forces d=s.
        root = (c0-k_r[0]) % p
        other_root = (k_beta-root) % p
        c1 = (k_r[1]+h0+h1) % p
        # The simulator uses only public tags, c0 and forward oracle answers.
        simulated_root = (c0+m_s0) % p
        simulated_other_root = (m_beta-simulated_root) % p
        simulated_c1 = (-m_s1+h0+h1) % p
        assert k_beta == m_beta
        assert simulated_root == root
        assert simulated_other_root == other_root
        assert simulated_c1 == c1


def test_prequery_bad_event_is_one_point_per_domain():
    p = 5
    # For fixed public data and beta != 0, Delta -> hidden is a bijection.
    beta = 3
    for m_beta, w, queried in product(range(p), repeat=3):
        hits = sum((m_beta-beta*delta-w) % p == queried
                   for delta in range(p))
        assert hits == 1

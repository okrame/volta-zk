"""Numerically vectorized execution shim for Code_estimators AGBforq.

The admissible integer (f, mu) search and estimator formula are unchanged.
NumPy longdouble replaces the legacy 170-digit Decimal inner loop; the
winning point is re-evaluated with the pinned Decimal implementation.
"""

import argparse

import numpy as np

from agb2.agb2 import degree_conjforq, subAGBforq


DT = np.longdouble


def scan(n: int, k: int, h: int):
    beta = n // h
    best = (float("inf"), -1, -1, -1)
    a1_outer = DT(-(n - k - h))
    a2_outer = DT(n - k - h) * DT(n - k - h - 1) / 2
    a3_outer = (
        -DT(n - k - h) * DT(n - k - h - 1) * DT(n - k - h - 2) / 6
    )
    a4_outer = (
        DT(n - k - h)
        * DT(n - k - h - 1)
        * DT(n - k - h - 2)
        * DT(n - k - h - 3)
        / 24
    )

    for f in range(h + 1):
        # f*mu < k+1 and mu=beta is the infinite-cost endpoint. For f=0
        # the formula is mu-independent, so one representative suffices.
        stop = 0 if f == 0 else min(beta - 1, k // f)
        mu = np.arange(stop + 1, dtype=DT)
        f_dt, h_dt, beta_dt = DT(f), DT(h), DT(beta)
        x = beta_dt - mu - 1

        b1 = x * f_dt
        b2 = x**2 * f_dt * DT(f - 1) / 2
        b3 = x**3 * f_dt * DT(f - 1) * DT(f - 2) / 6
        b4 = x**4 * f_dt * DT(f - 1) * DT(f - 2) * DT(f - 3) / 24
        y, h_minus_f = beta_dt - 1, DT(h - f)
        c1 = y * h_minus_f
        c2 = y**2 * h_minus_f * DT(h - f - 1) / 2
        c3 = y**3 * h_minus_f * DT(h - f - 1) * DT(h - f - 2) / 6
        c4 = (
            y**4
            * h_minus_f
            * DT(h - f - 1)
            * DT(h - f - 2)
            * DT(h - f - 3)
            / 24
        )

        degree_d2 = (
            a1_outer * b1
            + a1_outer * c1
            + b1 * c1
            + a2_outer
            + b2
            + c2
        )
        degree_d3 = (
            c3
            + b1 * c2
            + b2 * c1
            + b3
            + a1_outer * (b1 * c1 + b2 + c2)
            + a2_outer * (b1 + c1)
            + a3_outer
        )
        degree_d4 = (
            c4
            + b1 * c3
            + b2 * c2
            + b3 * c1
            + b4
            + a1_outer * (b1 * c2 + b2 * c1 + b3 + c3)
            + a2_outer * (b2 + c2 + b1 * c1)
            + a3_outer * (b1 + c1)
            + a4_outer
        )
        degree = np.full(stop + 1, 30, dtype=np.int8)
        is2 = degree_d2 < 1
        degree[is2] = 2
        is3 = (~is2) & ((degree_d2 + degree_d3) < 1)
        degree[is3] = 3
        is4 = (~is2) & (~is3) & ((degree_d2 + degree_d3 + degree_d4) < 1)
        degree[is4] = 4

        a1, a2, a3, a4 = b1, b2, b3, b4
        b1_inner, b2_inner, b3_inner, b4_inner = c1, c2, c3, c4
        c1_inner = DT(h - 1)
        c2_inner = DT(h) * DT(h - 1) / 2
        c3_inner = DT(h + 1) * DT(h) * DT(h - 1) / 6
        c4_inner = DT(h + 2) * DT(h + 1) * DT(h) * DT(h - 1) / 24
        matrix_d2 = (
            a1
            + b1_inner
            + c1_inner
            + a1 * b1_inner
            + a1 * c1_inner
            + b1_inner * c1_inner
            + a2
            + b2_inner
            + c2_inner
        )
        matrix_d3 = (
            c3_inner
            + b1_inner * c2_inner
            + b2_inner * c1_inner
            + b3_inner
            + a1 * (b1_inner * c1_inner + b2_inner + c2_inner)
            + a2 * (b1_inner + c1_inner)
            + a3
        )
        matrix_d4 = (
            c4_inner
            + b1_inner * c3_inner
            + b2_inner * c2_inner
            + b3_inner * c1_inner
            + b4_inner
            + a1 * (b1_inner * c2_inner + b2_inner * c1_inner + b3_inner + c3_inner)
            + a2 * (b2_inner + c2_inner + b1_inner * c1_inner)
            + a3 * (b1_inner + c1_inner)
            + a4
        )
        matrix_size = np.where(
            degree == 2,
            matrix_d2,
            np.where(
                degree == 3,
                matrix_d2 + matrix_d3,
                np.where(degree == 4, matrix_d2 + matrix_d3 + matrix_d4, np.nan),
            ),
        )
        valid = (
            (degree < 30)
            & (matrix_size > 0)
            & ((k + 1 - f * mu) > 0)
        )
        cost = np.full(stop + 1, np.inf, dtype=DT)
        cost[valid] = (
            2 * np.log2(matrix_size[valid])
            + np.log2(3 * (DT(k + 1) - f_dt * mu[valid]))
            - f_dt * np.log2(1 - mu[valid] / beta_dt)
        )
        index = int(np.argmin(cost))
        candidate = (float(cost[index]), f, index, int(degree[index]))
        if candidate < best:
            best = candidate

    exact = subAGBforq(n, k, h, best[1], best[2])
    assert degree_conjforq(n, k, h, best[1], best[2]) == best[3]
    return best, exact


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("n", type=int)
    parser.add_argument("k", type=int)
    parser.add_argument("t", type=int)
    args = parser.parse_args()
    approx, exact = scan(args.n, args.k, args.t)
    print(f"longdouble_min={approx}")
    print(f"decimal_exact={exact}")
    print(f"AGB={round(exact, 2)}")

"""Sparse-cache execution shim for Code_estimators OurAGB2forq.

The upstream cache is a default-float64 NumPy zero array. This shim preserves
its three-index API and float64 coercion while storing only written entries.
"""

import argparse

import agb2.agb2 as agb


class Sparse3:
    def __init__(self):
        self.values = {}

    def __getitem__(self, key):
        return Node(self, (key,))


class Node:
    def __init__(self, root, prefix):
        self.root = root
        self.prefix = prefix

    def __getitem__(self, key):
        path = self.prefix + (key,)
        return self.root.values.get(path, 0.0) if len(path) == 3 else Node(self.root, path)

    def __setitem__(self, key, value):
        self.root.values[self.prefix + (key,)] = float(value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("n", type=int)
    parser.add_argument("k", type=int)
    parser.add_argument("t", type=int)
    args = parser.parse_args()
    agb.np.zeros = lambda _shape: Sparse3()
    print(f"AGB2={agb.OurAGB2forq(args.n, args.k, args.t)}")

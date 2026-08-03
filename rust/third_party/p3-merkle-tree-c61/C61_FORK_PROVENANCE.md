# C6.1 Merkle-tree fork provenance

- Upstream repository: `https://github.com/Plonky3/Plonky3.git`
- Upstream revision: `66e290615de1858f2f2f6a804158064c406cda1c`
- Imported package: `merkle-tree` (`p3-merkle-tree` 0.6.0)
- VOLTA purpose: expose immutable post-commit views so `C6SPX1-v1` can
  persist and release prover data without changing tree construction or the
  verifier.

The only initial source delta is the three `c61_spill_*` read-only accessors
in `src/merkle_tree.rs`.  All hashing, compression, commitment, opening,
pruning and verification algorithms remain byte-for-byte upstream.

# p3-sumcheck C6.1 fork

Imported from Plonky3 commit
`66e290615de1858f2f2f6a804158064c406cda1c`, crate `sumcheck` version
`0.6.0`.  The source tree is copied verbatim before the C6.1 patches.

The fork exists only to add a typed claimless affine replay used by the
interactive designated-verifier C6.1 reference.  It is not a replacement for
the immutable `c61-p3-reference` dependency and is not a production fallback.

Exactly four source files differ from that revision:

- `src/zk/data.rs`: typed affine claim and verifier handoff;
- `src/zk/mod.rs`: exports those types;
- `src/zk/prover/residual.rs`: a claimless entry point which skips clear
  claim observation while preserving the original binding API; and
- `src/zk/verifier.rs`: shape-checked affine replay of every hidden-claim
  sumcheck round.

`../C61_P3_UPSTREAM_SHA256SUMS` pins all 87 imported Rust sources and
`../../../scripts/audit_c61_p3_fork.py` rejects any unregistered delta.  The
fork has no standalone `Cargo.lock` or crate-local `target/`; the VOLTA
workspace lock and target are binding.

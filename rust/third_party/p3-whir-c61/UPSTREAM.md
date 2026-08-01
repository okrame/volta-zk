# p3-whir C6.1 fork

Imported from Plonky3 commit
`66e290615de1858f2f2f6a804158064c406cda1c`, crate `whir` version `0.6.0`.
The source tree is copied verbatim before the C6.1 patches.

This fork is a feature-gated CPU reference for the claimless affine target
construction.  The immutable `c61-p3-reference` continues to use the original
git dependency, so historical C6WIR1 bytes and equations cannot change.

Exactly ten source files differ from that revision:

- `src/lib.rs` and `src/pcs/zk/mod.rs`: claimless API exports and removal of
  the old target-revealing adapter from this fork's public surface;
- `src/pcs/zk/proof.rs`: removes the clear evaluation vector;
- `src/pcs/zk/prover/mod.rs` and `src/pcs/zk/verifier/mod.rs`: one-opening
  claimless prover plus complete affine verifier replay through both
  sumcheck batches and public code-switch offsets;
- `src/pcs/zk/base_case/{mod.rs,prover.rs,verifier.rs}`: return the public
  base closure and accept the preconsumed C6AWH1 mask shift instead of
  checking a clear target; and
- `src/fiat_shamir/{domain_separator.rs,pattern.rs}`: compile-time cleanup
  after the target-revealing adapter is removed; protocol moves used by the
  claimless path are unchanged.

`../C61_P3_UPSTREAM_SHA256SUMS` pins all 87 imported Rust sources and
`../../../scripts/audit_c61_p3_fork.py` rejects any unregistered delta.  The
fork has no standalone `Cargo.lock` or crate-local `target/`; the VOLTA
workspace lock and target are binding.
No fork code is a production fallback.

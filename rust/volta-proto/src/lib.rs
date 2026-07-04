//! P3: blind sumcheck (M3 schema), Thaler matmul reduction, batched
//! QuickSilver product check (M7/M8), and the end-to-end blind GEMM proof
//! built on `volta-mac`'s authenticated values and mock-PCG correlations.
//! (LogUp arrives in P4; its clear spike lives in volta-bench::logup.)

pub mod gemm_proof;
pub mod mle;
pub mod prod_check;
pub mod sumcheck_blind;
pub mod sumcheck_clear;
pub mod thaler;

pub use gemm_proof::{auth_phase, prove_gemm_blind, verify_gemm_blind, GemmBlindProof, ProveTimings};
pub use prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
pub use sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
pub use sumcheck_clear::{prove_clear, verify_clear, ClearProof};

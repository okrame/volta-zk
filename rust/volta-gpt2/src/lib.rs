//! Fixed-point GPT-2 forward pass (= witness generation) and the integer GEMM
//! kernel with the fused MAC-authentication epilogue.
//!
//! P1 scope: the kernel + epilogue only. The full forward pass lands in P5.

pub mod gemm;

pub use gemm::{gemm_requant, gemm_requant_auth, EpilogueSpec};

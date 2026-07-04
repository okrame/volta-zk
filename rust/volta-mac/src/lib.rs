//! Authenticated values (`k = m + Δ·x`), Π_Auth, Π_ZeroOpen/ZeroBatch, and
//! mock-PCG correlation streams with domain-separated one-time indices.
//!
//! P2 milestone — implementation mirrors the Lean theorems: M1 (`Authed`,
//! `Valid` and linearity), M2 (ZeroOpen/ZeroBatch with fresh full-field
//! mask), M4/M6 (one-time domain-separated correlation indices, every
//! consumption counted), M5 (subfield `F_p` corrections, 8 B each).

pub mod auth;
pub mod authed;
pub mod corr;
pub mod open;
pub mod transcript;

pub use auth::{auth_prover, auth_verifier, auth_verifier_from_epilogue, prover_tags_from_epilogue};
pub use authed::{ProverAuthed, ProverSubAuthed, VerifierKey};
pub use corr::{CorrCounters, CorrIndex, CorrelationStream, FullCorr, SubCorr, VerifierCtx};
pub use open::{
    fresh_zero_mask, zero_batch_exchange, zero_batch_prover, zero_batch_verify, zero_mask_key,
    zero_open_prover, zero_open_verify,
};
pub use transcript::Transcript;

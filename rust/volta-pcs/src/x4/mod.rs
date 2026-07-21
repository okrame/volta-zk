//! X4 `x4-zkdeepfold-ud-e29-v2` implementation.
//!
//! This module is intentionally separate from the historical Ligero codec
//! and Merkle tree.  X4 hashes complete, canonical, domain-separated v2
//! frames; changing the legacy tree would change already-pinned roots.

pub mod folding;
pub mod frame;
pub mod merkle;
pub mod ntt;

pub use folding::*;
pub use frame::*;
pub use merkle::*;
pub use ntt::*;

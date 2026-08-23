//! HVZK-WHIR: honest-verifier zero-knowledge WHIR pipeline.
//!
//! Composes eprint 2026/391 into a hiding multilinear commitment scheme:
//!
//! ```text
//!     commit   : interleaved ZK Reed-Solomon encoding of the witness
//!     fold     : masked sumcheck batches        (Construction 6.3)
//!     reduce   : HVZK code-switching rounds     (Construction 9.7)
//!     finish   : non-succinct masked base case  (Construction 7.2)
//! ```
//!
//! # Relation carried between reductions
//!
//! The committed-sumcheck relation (Definition 5.8):
//!
//! ```text
//!     <f, W> + sum_i <xi_i, u_i> = target
//! ```
//!
//! - `f`: message of the current committed oracle, shrinking per fold.
//! - `W`: source covector, tracked symbolically by the verifier.
//! - `xi_i`: mask-oracle messages (sumcheck masks and code-switch masks).
//! - `u_i`: dense mask covectors of size `O~(lambda)`.
//!
//! # What is revealed
//!
//! Only the requested opening evaluations leave the prover unblinded:
//!
//! ```text
//!     sumcheck wires        ->  hidden by per-round masks
//!     out-of-domain answers ->  hidden by a private zero-evader pad
//!     query openings        ->  hidden by the encodings' randomness budget
//!     final message         ->  hidden by a fresh one-time mask
//! ```
//!
//! # Mask oracle grouping
//!
//! - Masks committed together share an evaluation domain.
//! - They stack into one interleaved oracle: one commitment per sumcheck
//!   batch, one per code-switching round.
//! - Base-case spot checks authenticate a whole group with a single Merkle
//!   path per position.
//! - The proof-size overhead stays an additive constant in the witness size.
//!
//! # Differences from the non-ZK pipeline
//!
//! - No commitment-phase out-of-domain samples: the round-by-round analysis
//!   of eprint 2026/391 replaces them with list-size union bounds.
//! - Per-round batching coefficients start at the first challenge power.
//!   The carried claim keeps coefficient one.
//!   Every fresh constraint gets an independent coefficient.
//! - Prefix variable order only.
//!
//! References:
//! - <https://eprint.iacr.org/2026/391> (HVZK-WHIR),
//! - <https://eprint.iacr.org/2024/1586> (base WHIR).

mod base_case;
mod code_switch;
mod committer;
mod config;
mod constraint;
mod mask;
mod proof;
mod prover;
mod verifier;

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_multilinear_util::point::Point;

use crate::pcs::proof::QueryOpenings;

/// Opt-in first-oracle decomposition used by C6.3.
///
/// The ordinary HVZK-WHIR path returns no extra values and is unchanged.  A
/// projected initial oracle may additionally expose the folded contribution
/// of its fresh encoding mask.  The first code-switch then proves that this
/// contribution is exactly `Enc(0, zeta)` rather than an arbitrary word that
/// could absorb a mismatch in the externally authenticated fixed base.
pub trait ZkWhirInitialOracleLink<F, EF, MT>
where
    F: Send + Sync + Clone,
    MT: Mmcs<F>,
{
    /// Whether absence of the extra first-round values is malformed.
    fn required(&self) -> bool;

    /// Returns one folded mask value per initial STIR query.
    fn folded_mask_values(
        &self,
        opening: &QueryOpenings<F, EF, MT::MultiProof>,
        indices: &[usize],
        randomness: &Point<EF>,
    ) -> Option<Vec<EF>>;
}

/// Historical no-link mode.  It preserves the exact original transcript and
/// proof bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoZkWhirInitialOracleLink;

impl<F, EF, MT> ZkWhirInitialOracleLink<F, EF, MT> for NoZkWhirInitialOracleLink
where
    F: Send + Sync + Clone,
    MT: Mmcs<F>,
{
    fn required(&self) -> bool {
        false
    }

    fn folded_mask_values(
        &self,
        _opening: &QueryOpenings<F, EF, MT::MultiProof>,
        _indices: &[usize],
        _randomness: &Point<EF>,
    ) -> Option<Vec<EF>> {
        None
    }
}

pub use base_case::{BaseCaseClaimlessClosure, BaseCaseZkError};
pub use code_switch::CodeSwitchError;
#[doc(hidden)]
pub use committer::c62_provider_cache_split_holds;
pub use config::{ZkConfigError, ZkParameters, ZkWhirConfig};
pub use mask::{MaskCodeShape, MaskGroupShape};
pub use proof::{BaseCaseZkProof, BlindedMask, MaskOpeningPair, ZkRoundProof, ZkWhirProof};
pub use prover::{
    ClaimlessWhirProverOutput, HidingWhirProver, HidingWhirProverData, ZkWhirOracleCommitter,
};
pub use verifier::{ClaimlessWhirVerifierClosure, HidingWhirVerifier, ZkVerifierError};

#[cfg(test)]
mod tests;

#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

pub mod fiat_shamir;
pub mod parameters;
pub mod pcs;
pub(crate) mod utils;

pub use fiat_shamir::domain_separator::DomainSeparator;
pub use p3_sumcheck::zk::AffineClaim as ClaimlessAffineClaim;
pub use parameters::{
    DEFAULT_MAX_POW, FoldingFactor, FoldingFactorError, ProtocolParameters, RoundConfig,
    SecurityAssumption, WhirConfig, WhirConfigError,
};
pub use pcs::WhirProverData;
pub use pcs::proof::{PcsProof, QueryOpenings, SharedProofOpening, WhirProof, WhirRoundProof};
pub use pcs::prover::WhirProver;
pub use pcs::verifier::WhirVerifier;
pub use pcs::verifier::errors::VerifierError;
pub use pcs::zk::{
    BaseCaseClaimlessClosure, BaseCaseZkError, BaseCaseZkProof, BlindedMask,
    ClaimlessWhirProverOutput, ClaimlessWhirVerifierClosure, CodeSwitchError, HidingWhirProver,
    HidingWhirProverData, HidingWhirVerifier, MaskCodeShape, MaskGroupShape, MaskOpeningPair,
    ZkConfigError, ZkParameters, ZkRoundProof, ZkVerifierError, ZkWhirConfig, ZkWhirProof,
};

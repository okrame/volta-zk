//! Typed assembly for C6.3's designated-verifier tail.

use volta_proto::{
    C63ResponseProofEnvelope, C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES,
    C62_RESPONSE_RESIDUAL_PENDING_BYTES, C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
    C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES, C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES,
    C63_RESPONSE_SPARSE_H_CLOSURE_BYTES, C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES,
};

use crate::c61_authenticated_whir::{
    C61AuthenticatedWhirBaseProof, C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
};
use crate::c63_sparse_h_closure::C63SparseHClosureProof;
use crate::c6_authenticated_output_link::{
    C63ResidualSourceFunctionalFrame, C6AuthenticatedOutputLinkProof,
    C63_AUTHENTICATED_SKETCH_OUTPUT_LINK_PRODUCTION_BYTES,
};
use crate::c6_wrapper_pcs::C6FixedWrapperCommitments;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63DecodedResponseTail {
    pub envelope: C63ResponseProofEnvelope,
    pub source_functional_corrections: C63ResidualSourceFunctionalFrame,
    pub authenticated_output_link: C6AuthenticatedOutputLinkProof,
    pub sparse_h_closure: C63SparseHClosureProof,
    pub whir_terminal_tags: [C61AuthenticatedWhirBaseProof; 4],
}

pub fn assemble_c63_response_tail(
    fixed: &C6FixedWrapperCommitments,
    residual_sumcheck: Vec<u8>,
    product_coordinate_one: Vec<u8>,
    residual_pending_corrections: Vec<u8>,
    source_functional_corrections: C63ResidualSourceFunctionalFrame,
    authenticated_output_link: &C6AuthenticatedOutputLinkProof,
    sparse_h_closure: &C63SparseHClosureProof,
    whir_terminal_tags: [C61AuthenticatedWhirBaseProof; 4],
) -> Result<Vec<u8>, String> {
    if C63_AUTHENTICATED_SKETCH_OUTPUT_LINK_PRODUCTION_BYTES
        != C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES
        || residual_sumcheck.len() as u64 > C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
        || product_coordinate_one.len() as u64 != C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES
        || residual_pending_corrections.len() as u64 != C62_RESPONSE_RESIDUAL_PENDING_BYTES
    {
        return Err("C6.3 response tail census differs".to_owned());
    }
    let authenticated_output_link =
        authenticated_output_link.canonical_bytes(fixed).map_err(|error| error.to_string())?;
    if authenticated_output_link.len() as u64 != C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES {
        return Err("C6.3 output-link size differs".to_owned());
    }
    let sparse_h_closure = sparse_h_closure.encode().map_err(|error| error.to_string())?;
    if sparse_h_closure.len() as u64 != C63_RESPONSE_SPARSE_H_CLOSURE_BYTES {
        return Err("C6.3 sparse-H size differs".to_owned());
    }
    let whir_terminal_tags = whir_terminal_tags
        .into_iter()
        .flat_map(C61AuthenticatedWhirBaseProof::encode)
        .collect::<Vec<_>>();
    if whir_terminal_tags.len() as u64 != C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES {
        return Err("C6.3 WHIR terminal-tag size differs".to_owned());
    }
    C63ResponseProofEnvelope::new(
        residual_sumcheck,
        product_coordinate_one,
        residual_pending_corrections,
        source_functional_corrections.encode().to_vec(),
        authenticated_output_link,
        sparse_h_closure,
        whir_terminal_tags,
    )
    .map_err(|error| error.to_string())?
    .encode()
    .map_err(|error| error.to_string())
}

pub fn decode_c63_response_tail(
    fixed: &C6FixedWrapperCommitments,
    bytes: &[u8],
) -> Result<C63DecodedResponseTail, String> {
    let envelope = C63ResponseProofEnvelope::decode(bytes).map_err(|error| error.to_string())?;
    if envelope.source_functional_corrections().len() as u64
        != C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES
    {
        return Err("C6.3 source-functional correction size differs".to_owned());
    }
    let source_functional_corrections =
        C63ResidualSourceFunctionalFrame::decode(envelope.source_functional_corrections())
            .map_err(|error| error.to_string())?;
    let authenticated_output_link =
        C6AuthenticatedOutputLinkProof::decode(fixed, envelope.authenticated_output_link())
            .map_err(|error| error.to_string())?;
    let sparse_h_closure = C63SparseHClosureProof::decode(envelope.sparse_h_closure())
        .map_err(|error| error.to_string())?;
    let tags = envelope
        .whir_terminal_tags()
        .chunks_exact(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .map(C61AuthenticatedWhirBaseProof::decode)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let whir_terminal_tags =
        tags.try_into().map_err(|_| "C6.3 WHIR terminal-tag census differs".to_owned())?;
    Ok(C63DecodedResponseTail {
        envelope,
        source_functional_corrections,
        authenticated_output_link,
        sparse_h_closure,
        whir_terminal_tags,
    })
}

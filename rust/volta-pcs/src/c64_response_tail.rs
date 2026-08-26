//! Strict C6.4 response tail: inherited residual/cache fields plus the
//! projected-residual frame, with no historical wrapper output-link.

use volta_proto::{
    C62_RESPONSE_CACHE_FOLD_TARGET_BYTES, C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES,
    C62_RESPONSE_RESIDUAL_PENDING_BYTES, C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
    C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES, C63_RESPONSE_SPARSE_H_CLOSURE_BYTES,
    C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES,
};

use crate::c61_authenticated_whir::{
    C61AuthenticatedWhirBaseProof, C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
};
use crate::c63_sparse_h_closure::C63SparseHClosureProof;
use crate::c64_projected_residual_codec::C64ProjectedResidualFrame;
use crate::c6_authenticated_output_link::C63ResidualSourceFunctionalFrame;

const MAGIC: [u8; 8] = *b"C64PIF1\0";
const VERSION: u16 = 1;
const COMPONENTS: usize = 8;
const HEADER_BYTES: usize = 8 + 2 + 2 + COMPONENTS * 8;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C64DecodedResponseTail {
    pub residual_sumcheck: Vec<u8>,
    pub product_coordinate_one: Vec<u8>,
    pub residual_pending_corrections: Vec<u8>,
    pub response_cache_fold_targets: Vec<u8>,
    pub source_functional_corrections: C63ResidualSourceFunctionalFrame,
    pub sparse_h_closure: C63SparseHClosureProof,
    pub cache_whir_terminal_tags: [C61AuthenticatedWhirBaseProof; 4],
    pub projected_residual: C64ProjectedResidualFrame,
}

impl C64DecodedResponseTail {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let payloads = self.payloads()?;
        let capacity = HEADER_BYTES + payloads.iter().map(Vec::len).sum::<usize>() + DIGEST_BYTES;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(COMPONENTS as u16).to_le_bytes());
        for payload in &payloads {
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        }
        for payload in payloads {
            bytes.extend_from_slice(&payload);
        }
        bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 8_500_000 {
            return Err("C6.4 response tail exceeds its cap".to_owned());
        }
        let mut cursor = Cursor { bytes, offset: 0 };
        if cursor.take(8)? != MAGIC
            || cursor.u16()? != VERSION
            || usize::from(cursor.u16()?) != COMPONENTS
        {
            return Err("C6.4 response tail header differs".to_owned());
        }
        let lengths = (0..COMPONENTS)
            .map(|_| cursor.u64().map(|value| value as usize))
            .collect::<Result<Vec<_>, _>>()?;
        let payloads = lengths
            .into_iter()
            .map(|length| cursor.take(length).map(<[u8]>::to_vec))
            .collect::<Result<Vec<_>, _>>()?;
        let digest_offset = cursor.offset;
        if cursor.take(32)? != blake3::hash(&bytes[..digest_offset]).as_bytes()
            || cursor.offset != bytes.len()
        {
            return Err("C6.4 response tail digest or trailing bytes differ".to_owned());
        }
        let mut payloads = payloads.into_iter();
        let residual_sumcheck = payloads.next().expect("fixed component census");
        let product_coordinate_one = payloads.next().expect("fixed component census");
        let residual_pending_corrections = payloads.next().expect("fixed component census");
        let response_cache_fold_targets = payloads.next().expect("fixed component census");
        let source_functional_corrections = C63ResidualSourceFunctionalFrame::decode(
            &payloads.next().expect("fixed component census"),
        )
        .map_err(|error| error.to_string())?;
        let sparse_h_closure =
            C63SparseHClosureProof::decode(&payloads.next().expect("fixed component census"))
                .map_err(|error| error.to_string())?;
        let tags = payloads.next().expect("fixed component census");
        let cache_whir_terminal_tags = tags
            .chunks_exact(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
            .map(C61AuthenticatedWhirBaseProof::decode)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "C6.4 cache WHIR terminal-tag census differs".to_owned())?;
        let projected_residual =
            C64ProjectedResidualFrame::decode(&payloads.next().expect("fixed component census"))?;
        let tail = Self {
            residual_sumcheck,
            product_coordinate_one,
            residual_pending_corrections,
            response_cache_fold_targets,
            source_functional_corrections,
            sparse_h_closure,
            cache_whir_terminal_tags,
            projected_residual,
        };
        tail.validate()?;
        if tail.encode()? != bytes {
            return Err("C6.4 response tail is noncanonical".to_owned());
        }
        Ok(tail)
    }

    fn payloads(&self) -> Result<[Vec<u8>; COMPONENTS], String> {
        self.validate()?;
        Ok([
            self.residual_sumcheck.clone(),
            self.product_coordinate_one.clone(),
            self.residual_pending_corrections.clone(),
            self.response_cache_fold_targets.clone(),
            self.source_functional_corrections.encode().to_vec(),
            self.sparse_h_closure.encode().map_err(|error| error.to_string())?,
            self.cache_whir_terminal_tags.iter().flat_map(|proof| proof.encode()).collect(),
            self.projected_residual.encode()?,
        ])
    }

    fn validate(&self) -> Result<(), String> {
        if self.residual_sumcheck.len() as u64 > C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
            || self.product_coordinate_one.len() as u64 != C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES
            || self.residual_pending_corrections.len() as u64 != C62_RESPONSE_RESIDUAL_PENDING_BYTES
            || self.response_cache_fold_targets.len() as u64 != C62_RESPONSE_CACHE_FOLD_TARGET_BYTES
            || C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES != 64
            || self.sparse_h_closure.encoded_len().map_err(|error| error.to_string())?
                != C63_RESPONSE_SPARSE_H_CLOSURE_BYTES
            || self.cache_whir_terminal_tags.len() as u64 * 16
                != C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES
        {
            return Err("C6.4 response tail component census differs".to_owned());
        }
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "C6.4 response tail cursor overflows".to_owned())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "C6.4 response tail is truncated".to_owned())?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }
}

//! Strict wire frame for the C6.4 projected residual suffix.

use volta_field::{Fp, Fp2, P};

use crate::c61_authenticated_whir::C61AuthenticatedWhirBaseProof;
use crate::c63_sparse_h_closure::{
    C63SparseHClosureProof, C64_CORRECTION_LINK_PRODUCTION_FRAMED_BYTES,
    C64_CORRECTION_LINK_PRODUCTION_ROUNDS,
};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c64_projected_residual_suffix::C64ProjectedResidualProverOutput;
use crate::c64_whir_profile::{c64_whir_structural_screen, C64_PROJECTED_RESIDUAL_BODIES};

const MAGIC: [u8; 8] = *b"C64PRS1\0";
const VERSION: u16 = 1;
const FAMILIES: usize = 3;
const LIMBS: usize = 2;
const ROOT_BYTES: usize = C64_PROJECTED_RESIDUAL_BODIES * 32;
const CORRECTION_BYTES: usize = FAMILIES * 2 * LIMBS * 16;
const TAG_BYTES: usize = FAMILIES * 2 * 16;
const HEADER_BYTES: usize = 8 + 2 + 2 + 32 + ROOT_BYTES + 8 + C64_PROJECTED_RESIDUAL_BODIES * 8;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C64ProjectedResidualFrame {
    pub binding_digest: [u8; 32],
    pub roots: [[u8; 32]; C64_PROJECTED_RESIDUAL_BODIES],
    pub artifacts: [[Vec<u8>; LIMBS]; FAMILIES],
    pub mask_corrections: [[[Fp2; LIMBS]; 2]; FAMILIES],
    pub terminal_proofs: [[C61AuthenticatedWhirBaseProof; 2]; FAMILIES],
    pub correction_link: C63SparseHClosureProof,
}

impl C64ProjectedResidualFrame {
    #[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
    pub(crate) fn from_output(
        binding_digest: [u8; 32],
        roots: [[u8; 32]; C64_PROJECTED_RESIDUAL_BODIES],
        output: C64ProjectedResidualProverOutput,
    ) -> Result<Self, String> {
        let frame = Self {
            binding_digest,
            roots,
            artifacts: output.artifacts,
            mask_corrections: output.mask_corrections,
            terminal_proofs: output.terminal_proofs,
            correction_link: output.correction_link,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let correction_link = self.correction_link.encode().map_err(|error| error.to_string())?;
        let capacity = HEADER_BYTES
            + self.artifacts.iter().flatten().map(Vec::len).sum::<usize>()
            + correction_link.len()
            + CORRECTION_BYTES
            + TAG_BYTES
            + DIGEST_BYTES;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C64_PROJECTED_RESIDUAL_BODIES as u16).to_le_bytes());
        bytes.extend_from_slice(&self.binding_digest);
        for root in self.roots {
            bytes.extend_from_slice(&root);
        }
        bytes.extend_from_slice(&(correction_link.len() as u64).to_le_bytes());
        for artifact in self.artifacts.iter().flatten() {
            bytes.extend_from_slice(&(artifact.len() as u64).to_le_bytes());
        }
        for artifact in self.artifacts.iter().flatten() {
            bytes.extend_from_slice(artifact);
        }
        bytes.extend_from_slice(&correction_link);
        for value in self.mask_corrections.iter().flatten().flatten() {
            encode_fp2(&mut bytes, *value);
        }
        for proof in self.terminal_proofs.iter().flatten() {
            bytes.extend_from_slice(&proof.encode());
        }
        bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
        if bytes.len() != capacity {
            return Err("C6.4 projected residual encoded census differs".to_owned());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 7_500_000 {
            return Err("C6.4 projected residual frame exceeds its cap".to_owned());
        }
        let mut cursor = Cursor { bytes, offset: 0 };
        if cursor.take(8)? != MAGIC
            || cursor.u16()? != VERSION
            || usize::from(cursor.u16()?) != C64_PROJECTED_RESIDUAL_BODIES
        {
            return Err("C6.4 projected residual header differs".to_owned());
        }
        let binding_digest = cursor.digest()?;
        let mut roots = [[0u8; 32]; C64_PROJECTED_RESIDUAL_BODIES];
        for root in &mut roots {
            *root = cursor.digest()?;
        }
        let correction_len = cursor.u64()? as usize;
        let mut artifact_lengths = [0usize; C64_PROJECTED_RESIDUAL_BODIES];
        for length in &mut artifact_lengths {
            *length = cursor.u64()? as usize;
        }
        let artifacts_flat = artifact_lengths
            .into_iter()
            .map(|length| cursor.take(length).map(<[u8]>::to_vec))
            .collect::<Result<Vec<_>, _>>()?;
        let artifacts: [[Vec<u8>; LIMBS]; FAMILIES] = artifacts_flat
            .chunks_exact(LIMBS)
            .map(|family| family.to_vec().try_into().expect("fixed limb census"))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "C6.4 projected residual family census differs".to_owned())?;
        let correction_link = C63SparseHClosureProof::decode(cursor.take(correction_len)?)
            .map_err(|error| error.to_string())?;
        let mut mask_corrections = [[[Fp2::ZERO; LIMBS]; 2]; FAMILIES];
        for value in mask_corrections.iter_mut().flatten().flatten() {
            *value = cursor.fp2()?;
        }
        let mut terminal_proofs = [[C61AuthenticatedWhirBaseProof::decode(&[0; 16])
            .map_err(|error| error.to_string())?; 2]; FAMILIES];
        for proof in terminal_proofs.iter_mut().flatten() {
            *proof = C61AuthenticatedWhirBaseProof::decode(cursor.take(16)?)
                .map_err(|error| error.to_string())?;
        }
        let digest_offset = cursor.offset;
        if cursor.digest()? != *blake3::hash(&bytes[..digest_offset]).as_bytes()
            || cursor.offset != bytes.len()
        {
            return Err("C6.4 projected residual digest or trailing bytes differ".to_owned());
        }
        let frame = Self {
            binding_digest,
            roots,
            artifacts,
            mask_corrections,
            terminal_proofs,
            correction_link,
        };
        frame.validate()?;
        if frame.encode()? != bytes {
            return Err("C6.4 projected residual encoding is noncanonical".to_owned());
        }
        Ok(frame)
    }

    fn validate(&self) -> Result<(), String> {
        let screen = c64_whir_structural_screen()?;
        let limits = [
            screen.projected_leaf.strict_chain_bytes,
            screen.projected_correction.strict_chain_bytes,
            screen.projected_auxiliary.strict_chain_bytes,
        ];
        if self.binding_digest == [0; 32]
            || self.roots.contains(&[0; 32])
            || self.artifacts.iter().enumerate().any(|(family, limbs)| {
                limbs.iter().any(|artifact| artifact.is_empty() || artifact.len() > limits[family])
            })
            || self.correction_link.round_count() != C64_CORRECTION_LINK_PRODUCTION_ROUNDS as usize
            || self.correction_link.encoded_len().map_err(|error| error.to_string())?
                != C64_CORRECTION_LINK_PRODUCTION_FRAMED_BYTES
        {
            return Err("C6.4 projected residual frame shape differs".to_owned());
        }
        Ok(())
    }
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
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
            .ok_or_else(|| "C6.4 projected residual cursor overflows".to_owned())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "C6.4 projected residual frame is truncated".to_owned())?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn digest(&mut self) -> Result<[u8; 32], String> {
        self.take(32)?
            .try_into()
            .map_err(|_| "C6.4 projected residual digest is truncated".to_owned())
    }

    fn fp2(&mut self) -> Result<Fp2, String> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err("C6.4 projected residual field element is noncanonical".to_owned());
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c63_sparse_h_closure::c64_correction_link_production_codec_reference;

    fn frame() -> C64ProjectedResidualFrame {
        let tag = C61AuthenticatedWhirBaseProof::decode(&[0; 16]).unwrap();
        C64ProjectedResidualFrame {
            binding_digest: [3; 32],
            roots: [[2; 32]; C64_PROJECTED_RESIDUAL_BODIES],
            artifacts: std::array::from_fn(|_| std::array::from_fn(|_| vec![1])),
            mask_corrections: [[[Fp2::ZERO; LIMBS]; 2]; FAMILIES],
            terminal_proofs: [[tag; 2]; FAMILIES],
            correction_link: c64_correction_link_production_codec_reference(),
        }
    }

    #[test]
    fn c64_projected_frame_round_trips_and_rejects_mutation() {
        let frame = frame();
        let bytes = frame.encode().unwrap();
        assert_eq!(C64ProjectedResidualFrame::decode(&bytes).unwrap(), frame);
        let mut changed = bytes;
        changed[12] ^= 1;
        assert!(C64ProjectedResidualFrame::decode(&changed).is_err());
    }
}

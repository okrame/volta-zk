//! Canonical tagless C6.3 public argument.

use crate::c63_authenticated_sketch::C63CorrectionRowsOpeningReference;
use crate::c63_preencoded_whir::{
    c63_whir_config, decode_c63_whir_ordinary_artifact_with_config,
    decode_c63_whir_projected_artifact_with_config, encode_c63_whir_ordinary_artifact_with_config,
    encode_c63_whir_projected_artifact_with_config, C63WhirConfig,
};

pub const C63_PUBLIC_ARGUMENT_MAGIC: [u8; 8] = *b"C63PUB1\0";
pub const C63_PUBLIC_ARGUMENT_VERSION: u16 = 1;
pub const C63_PUBLIC_ARGUMENT_COMPONENTS: usize = 5;
pub const C63_CORRECTION_OPENING_MAX_BYTES: usize = 2_037_262;
pub const C63_PUBLIC_ARGUMENT_FRAMING_BYTES: usize = 384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63PublicArgument {
    statement_digest: [u8; 32],
    profile_digest: [u8; 32],
    correction_root: [u8; 32],
    encoded_sketch_root: [u8; 32],
    epoch: u64,
    accepted_len: u16,
    correction_opening: Vec<u8>,
    d22_whir: [Vec<u8>; 2],
    d19_projected_whir: [Vec<u8>; 2],
}

impl C63PublicArgument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        statement_digest: [u8; 32],
        profile_digest: [u8; 32],
        correction_root: [u8; 32],
        encoded_sketch_root: [u8; 32],
        epoch: u64,
        accepted_len: u16,
        queried_rows: &[u32],
        correction_opening: Vec<u8>,
        d22_whir: [Vec<u8>; 2],
        d19_projected_whir: [Vec<u8>; 2],
    ) -> Result<Self, String> {
        Self::new_with_configs(
            statement_digest,
            profile_digest,
            correction_root,
            encoded_sketch_root,
            epoch,
            accepted_len,
            queried_rows,
            correction_opening,
            d22_whir,
            d19_projected_whir,
            22,
            &c63_whir_config(22)?,
            19,
            &c63_whir_config(19)?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_configs(
        statement_digest: [u8; 32],
        profile_digest: [u8; 32],
        correction_root: [u8; 32],
        encoded_sketch_root: [u8; 32],
        epoch: u64,
        accepted_len: u16,
        queried_rows: &[u32],
        correction_opening: Vec<u8>,
        d22_whir: [Vec<u8>; 2],
        d19_projected_whir: [Vec<u8>; 2],
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<Self, String> {
        let argument = Self {
            statement_digest,
            profile_digest,
            correction_root,
            encoded_sketch_root,
            epoch,
            accepted_len,
            correction_opening,
            d22_whir,
            d19_projected_whir,
        };
        argument.validate_with_configs(
            queried_rows,
            input_variables,
            input_config,
            output_variables,
            output_config,
        )?;
        Ok(argument)
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn correction_root(&self) -> [u8; 32] {
        self.correction_root
    }

    pub fn encoded_sketch_root(&self) -> [u8; 32] {
        self.encoded_sketch_root
    }

    pub fn correction_opening(&self) -> &[u8] {
        &self.correction_opening
    }

    pub fn d22_whir(&self) -> &[Vec<u8>; 2] {
        &self.d22_whir
    }

    pub fn d19_projected_whir(&self) -> &[Vec<u8>; 2] {
        &self.d19_projected_whir
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let components = self.components();
        let payload_bytes = components.iter().map(|(_, payload)| payload.len()).sum::<usize>();
        let mut bytes = Vec::with_capacity(C63_PUBLIC_ARGUMENT_FRAMING_BYTES + payload_bytes);
        bytes.extend_from_slice(&C63_PUBLIC_ARGUMENT_MAGIC);
        bytes.extend_from_slice(&C63_PUBLIC_ARGUMENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C63_PUBLIC_ARGUMENT_COMPONENTS as u16).to_le_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.accepted_len.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for digest in [
            self.statement_digest,
            self.profile_digest,
            self.correction_root,
            self.encoded_sketch_root,
        ] {
            bytes.extend_from_slice(&digest);
        }
        for (kind, payload) in components {
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| "C6.3 public component exceeds u32".to_owned())?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&component_digest(kind, payload));
            bytes.extend_from_slice(payload);
        }
        bytes.extend_from_slice(&argument_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], queried_rows: &[u32]) -> Result<Self, String> {
        let input_config = c63_whir_config(22)?;
        let output_config = c63_whir_config(19)?;
        Self::decode_with_configs(bytes, queried_rows, 22, &input_config, 19, &output_config)
    }

    pub(crate) fn decode_with_configs(
        bytes: &[u8],
        queried_rows: &[u32],
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<Self, String> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C63_PUBLIC_ARGUMENT_MAGIC
            || cursor.u16()? != C63_PUBLIC_ARGUMENT_VERSION
            || usize::from(cursor.u16()?) != C63_PUBLIC_ARGUMENT_COMPONENTS
        {
            return Err("C6.3 public argument header differs".to_owned());
        }
        let epoch = cursor.u64()?;
        let accepted_len = cursor.u16()?;
        if cursor.u16()? != 0 {
            return Err("C6.3 public argument reserved field differs".to_owned());
        }
        let statement_digest = cursor.digest()?;
        let profile_digest = cursor.digest()?;
        let correction_root = cursor.digest()?;
        let encoded_sketch_root = cursor.digest()?;
        let mut components = Vec::with_capacity(C63_PUBLIC_ARGUMENT_COMPONENTS);
        for expected_kind in 1..=C63_PUBLIC_ARGUMENT_COMPONENTS as u16 {
            if cursor.u16()? != expected_kind || cursor.u16()? != 0 {
                return Err("C6.3 public component order differs".to_owned());
            }
            let len = cursor.u32()? as usize;
            let digest = cursor.digest()?;
            let payload = cursor.take(len)?.to_vec();
            if digest != component_digest(expected_kind, &payload) {
                return Err("C6.3 public component digest differs".to_owned());
            }
            components.push(payload);
        }
        let digest_offset = cursor.offset;
        if cursor.digest()? != argument_digest(&bytes[..digest_offset]) {
            return Err("C6.3 public argument digest differs".to_owned());
        }
        cursor.finish()?;
        let components: [Vec<u8>; C63_PUBLIC_ARGUMENT_COMPONENTS] =
            components.try_into().map_err(|_| "C6.3 public component census differs".to_owned())?;
        let [correction_opening, d22_0, d22_1, d19_0, d19_1] = components;
        let argument = Self::new_with_configs(
            statement_digest,
            profile_digest,
            correction_root,
            encoded_sketch_root,
            epoch,
            accepted_len,
            queried_rows,
            correction_opening,
            [d22_0, d22_1],
            [d19_0, d19_1],
            input_variables,
            input_config,
            output_variables,
            output_config,
        )?;
        if argument.encode()?.as_slice() != bytes {
            return Err("noncanonical C6.3 public argument".to_owned());
        }
        Ok(argument)
    }

    fn components(&self) -> [(u16, &[u8]); C63_PUBLIC_ARGUMENT_COMPONENTS] {
        [
            (1, &self.correction_opening),
            (2, &self.d22_whir[0]),
            (3, &self.d22_whir[1]),
            (4, &self.d19_projected_whir[0]),
            (5, &self.d19_projected_whir[1]),
        ]
    }

    fn validate_with_configs(
        &self,
        queried_rows: &[u32],
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<(), String> {
        if [
            self.statement_digest,
            self.profile_digest,
            self.correction_root,
            self.encoded_sketch_root,
        ]
        .contains(&[0; 32])
            || self.epoch == 0
            || self.accepted_len == 0
            || self.correction_opening.len() > C63_CORRECTION_OPENING_MAX_BYTES
        {
            return Err("C6.3 public argument metadata differs".to_owned());
        }
        let correction = C63CorrectionRowsOpeningReference::decode(
            &self.correction_opening,
            self.accepted_len,
            queried_rows,
        )?;
        if correction.encode(self.accepted_len, queried_rows)? != self.correction_opening {
            return Err("noncanonical C6.3 correction opening".to_owned());
        }
        for artifact in &self.d22_whir {
            let (commitment, proof) = decode_c63_whir_ordinary_artifact_with_config(
                artifact,
                input_variables,
                input_config,
            )?;
            if encode_c63_whir_ordinary_artifact_with_config(
                input_variables,
                input_config,
                &commitment,
                &proof,
            )? != *artifact
            {
                return Err("noncanonical C6.3 D22 WHIR artifact".to_owned());
            }
        }
        for artifact in &self.d19_projected_whir {
            let (commitment, proof) = decode_c63_whir_projected_artifact_with_config(
                artifact,
                output_variables,
                output_config,
            )?;
            if encode_c63_whir_projected_artifact_with_config(
                output_variables,
                output_config,
                &commitment,
                &proof,
            )? != *artifact
            {
                return Err("noncanonical C6.3 projected WHIR artifact".to_owned());
            }
        }
        Ok(())
    }
}

fn component_digest(kind: u16, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-component/v1");
    hasher.update(&kind.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn argument_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-argument/v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(len).ok_or("C6.3 public cursor overflow")?;
        let value = self.bytes.get(self.offset..end).ok_or("truncated C6.3 public argument")?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    fn digest(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().expect("digest width"))
    }

    fn finish(self) -> Result<(), String> {
        if self.offset != self.bytes.len() {
            return Err("trailing C6.3 public argument bytes".to_owned());
        }
        Ok(())
    }
}

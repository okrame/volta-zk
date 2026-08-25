//! Canonical tagless C6.3 public argument.

use crate::c61_whir_reference::C61Commitment;
use crate::c63_authenticated_sketch::C63_BOLT_COLUMNS;
use crate::c63_authenticated_sketch::{
    C63CorrectionAppendFrontier, C63CorrectionRowsOpeningReference,
};
use crate::c63_preencoded_whir::{
    c63_challenger, c63_sample_systematic_query_rows, c63_whir_config, c63_whir_initial_roots,
    decode_c63_whir_ordinary_artifact_with_config, decode_c63_whir_projected_artifact_with_config,
    encode_c63_whir_ordinary_artifact_with_config, encode_c63_whir_projected_artifact_with_config,
    C63EncodedSketchAtoYContext, C63TranscriptBinding, C63WhirConfig,
};
use volta_field::Fp2;
use volta_proto::C6ClientAttempt;

pub const C63_PUBLIC_ARGUMENT_MAGIC: [u8; 8] = *b"C63PUB3\0";
pub const C63_PUBLIC_ARGUMENT_VERSION: u16 = 3;
pub const C63_PUBLIC_ARGUMENT_COMPONENTS: usize = 9;
pub const C63_CORRECTION_OPENING_MAX_BYTES: usize = 2_042_062;
pub const C63_PUBLIC_ARGUMENT_FRAMING_BYTES: usize = 608;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63PublicArgument {
    statement_digest: [u8; 32],
    profile_digest: [u8; 32],
    predecessor_correction_root: [u8; 32],
    predecessor_encoded_sketch_root: [u8; 32],
    correction_root: [u8; 32],
    encoded_sketch_root: [u8; 32],
    epoch: u64,
    old_len: u16,
    accepted_len: u16,
    correction_opening: Vec<u8>,
    d22_whir: [[Vec<u8>; 2]; 2],
    d19_projected_whir: [[Vec<u8>; 2]; 2],
}

pub(crate) struct C63TranscriptPublicArgument {
    pub(crate) argument: C63PublicArgument,
    pub(crate) binding: C63TranscriptBinding,
    pub(crate) rho: [Fp2; C63_BOLT_COLUMNS],
    pub(crate) projected_contexts: [[C63EncodedSketchAtoYContext; 2]; 2],
    pub(crate) queried_rows: Vec<u32>,
}

/// Connection-scoped C6.3 state retained by the CPU verifier. The outer C6
/// client state retains the accepted head and replay counters; this compact
/// record retains only the two child roots and correction-tree frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63VerifierSketchState {
    profile_digest: [u8; 32],
    epoch: u64,
    accepted_len: u16,
    correction_root: [u8; 32],
    encoded_sketch_root: [u8; 32],
    correction_frontier: C63CorrectionAppendFrontier,
}

impl C63VerifierSketchState {
    pub fn genesis(
        profile_digest: [u8; 32],
        zero_encoded_sketch_root: [u8; 32],
    ) -> Result<Self, String> {
        if profile_digest == [0; 32] || zero_encoded_sketch_root == [0; 32] {
            return Err("C6.3 verifier genesis contains an empty root".to_owned());
        }
        let correction_frontier = C63CorrectionAppendFrontier::zero();
        let correction_root = correction_frontier.state_root(profile_digest, 0)?;
        Ok(Self {
            profile_digest,
            epoch: 0,
            accepted_len: 0,
            correction_root,
            encoded_sketch_root: zero_encoded_sketch_root,
            correction_frontier,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn accepted_len(&self) -> u16 {
        self.accepted_len
    }

    pub fn correction_root(&self) -> [u8; 32] {
        self.correction_root
    }

    pub fn encoded_sketch_root(&self) -> [u8; 32] {
        self.encoded_sketch_root
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        profile_digest: [u8; 32],
        epoch: u64,
        encoded_sketch_root: [u8; 32],
        correction_frontier: C63CorrectionAppendFrontier,
    ) -> Result<Self, String> {
        if profile_digest == [0; 32] || encoded_sketch_root == [0; 32] {
            return Err("C6.3 verifier test state contains an empty root".to_owned());
        }
        let accepted_len = correction_frontier.accepted_len();
        let correction_root = correction_frontier.state_root(profile_digest, epoch)?;
        Ok(Self {
            profile_digest,
            epoch,
            accepted_len,
            correction_root,
            encoded_sketch_root,
            correction_frontier,
        })
    }

    pub(crate) fn correction_frontier(&self) -> &C63CorrectionAppendFrontier {
        &self.correction_frontier
    }

    pub(crate) fn accept(
        &self,
        argument: &C63PublicArgument,
        correction_frontier: C63CorrectionAppendFrontier,
    ) -> Result<Self, String> {
        if argument.profile_digest != self.profile_digest
            || argument.epoch != self.epoch.checked_add(1).ok_or("C6.3 verifier epoch overflows")?
            || argument.old_len != self.accepted_len
            || argument.predecessor_correction_root != self.correction_root
            || argument.predecessor_encoded_sketch_root != self.encoded_sketch_root
            || correction_frontier.accepted_len() != argument.accepted_len
        {
            return Err("C6.3 verifier predecessor state differs".to_owned());
        }
        Ok(Self {
            profile_digest: self.profile_digest,
            epoch: argument.epoch,
            accepted_len: argument.accepted_len,
            correction_root: argument.correction_root,
            encoded_sketch_root: argument.encoded_sketch_root,
            correction_frontier,
        })
    }
}

impl C63PublicArgument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        statement_digest: [u8; 32],
        profile_digest: [u8; 32],
        predecessor_correction_root: [u8; 32],
        predecessor_encoded_sketch_root: [u8; 32],
        correction_root: [u8; 32],
        encoded_sketch_root: [u8; 32],
        epoch: u64,
        old_len: u16,
        accepted_len: u16,
        queried_rows: &[u32],
        correction_opening: Vec<u8>,
        d22_whir: [[Vec<u8>; 2]; 2],
        d19_projected_whir: [[Vec<u8>; 2]; 2],
    ) -> Result<Self, String> {
        Self::new_with_configs(
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_encoded_sketch_root,
            correction_root,
            encoded_sketch_root,
            epoch,
            old_len,
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
        predecessor_correction_root: [u8; 32],
        predecessor_encoded_sketch_root: [u8; 32],
        correction_root: [u8; 32],
        encoded_sketch_root: [u8; 32],
        epoch: u64,
        old_len: u16,
        accepted_len: u16,
        queried_rows: &[u32],
        correction_opening: Vec<u8>,
        d22_whir: [[Vec<u8>; 2]; 2],
        d19_projected_whir: [[Vec<u8>; 2]; 2],
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<Self, String> {
        let argument = Self {
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_encoded_sketch_root,
            correction_root,
            encoded_sketch_root,
            epoch,
            old_len,
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

    pub fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    pub fn correction_root(&self) -> [u8; 32] {
        self.correction_root
    }

    pub fn predecessor_correction_root(&self) -> [u8; 32] {
        self.predecessor_correction_root
    }

    pub fn predecessor_encoded_sketch_root(&self) -> [u8; 32] {
        self.predecessor_encoded_sketch_root
    }

    pub fn encoded_sketch_root(&self) -> [u8; 32] {
        self.encoded_sketch_root
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn accepted_len(&self) -> u16 {
        self.accepted_len
    }

    pub fn old_len(&self) -> u16 {
        self.old_len
    }

    pub fn correction_opening(&self) -> &[u8] {
        &self.correction_opening
    }

    pub fn d22_whir(&self) -> &[[Vec<u8>; 2]; 2] {
        &self.d22_whir
    }

    pub fn d19_projected_whir(&self) -> &[[Vec<u8>; 2]; 2] {
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
        bytes.extend_from_slice(&self.old_len.to_le_bytes());
        bytes.extend_from_slice(&self.accepted_len.to_le_bytes());
        for digest in [
            self.statement_digest,
            self.profile_digest,
            self.predecessor_correction_root,
            self.predecessor_encoded_sketch_root,
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_in_attempt_with_configs(
        bytes: &[u8],
        attempt: C6ClientAttempt,
        spot_queries: usize,
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<C63TranscriptPublicArgument, String> {
        let argument = Self::decode_framing(bytes)?;
        let binding = C63TranscriptBinding::new(
            attempt,
            argument.statement_digest,
            argument.profile_digest,
            argument.predecessor_correction_root,
            argument.predecessor_encoded_sketch_root,
            argument.correction_root,
            argument.encoded_sketch_root,
            argument.epoch,
            argument.old_len,
            argument.accepted_len,
        )?;
        let mut rho_challenger = c63_challenger(binding.rho_seed())?;
        let rows = 1usize
            .checked_shl(output_variables as u32)
            .ok_or_else(|| "C6.3 encoded-sketch geometry overflows".to_owned())?;
        let (rho, projected_contexts) = C63EncodedSketchAtoYContext::sample_tape_limb_after_roots(
            C61Commitment::new(vec![argument.predecessor_correction_root]),
            C61Commitment::new(vec![argument.predecessor_encoded_sketch_root]),
            C61Commitment::new(vec![argument.correction_root]),
            C61Commitment::new(vec![argument.encoded_sketch_root]),
            argument.old_len,
            rows,
            &mut rho_challenger,
        )?;
        let initial_roots = c63_whir_initial_roots(
            &argument.d22_whir,
            &argument.d19_projected_whir,
            input_variables,
            output_variables,
        )?;
        let query_seed = binding.query_seed(&rho, &initial_roots)?;
        let mut spot_challenger = c63_challenger(binding.spot_seed(query_seed)?)?;
        let queried_rows =
            c63_sample_systematic_query_rows(&mut spot_challenger, input_variables, spot_queries)?;
        argument.validate_with_configs(
            &queried_rows,
            input_variables,
            input_config,
            output_variables,
            output_config,
        )?;
        if argument.encode()?.as_slice() != bytes {
            return Err("noncanonical C6.3 public argument".to_owned());
        }
        Ok(C63TranscriptPublicArgument { argument, binding, rho, projected_contexts, queried_rows })
    }

    pub(crate) fn decode_with_configs(
        bytes: &[u8],
        queried_rows: &[u32],
        input_variables: usize,
        input_config: &C63WhirConfig,
        output_variables: usize,
        output_config: &C63WhirConfig,
    ) -> Result<Self, String> {
        let argument = Self::decode_framing(bytes)?;
        argument.validate_with_configs(
            queried_rows,
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

    fn decode_framing(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C63_PUBLIC_ARGUMENT_MAGIC
            || cursor.u16()? != C63_PUBLIC_ARGUMENT_VERSION
            || usize::from(cursor.u16()?) != C63_PUBLIC_ARGUMENT_COMPONENTS
        {
            return Err("C6.3 public argument header differs".to_owned());
        }
        let epoch = cursor.u64()?;
        let old_len = cursor.u16()?;
        let accepted_len = cursor.u16()?;
        let statement_digest = cursor.digest()?;
        let profile_digest = cursor.digest()?;
        let predecessor_correction_root = cursor.digest()?;
        let predecessor_encoded_sketch_root = cursor.digest()?;
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
        let [correction_opening, d22_00, d22_01, d22_10, d22_11, d19_00, d19_01, d19_10, d19_11] =
            components;
        Ok(Self {
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_encoded_sketch_root,
            correction_root,
            encoded_sketch_root,
            epoch,
            old_len,
            accepted_len,
            correction_opening,
            d22_whir: [[d22_00, d22_01], [d22_10, d22_11]],
            d19_projected_whir: [[d19_00, d19_01], [d19_10, d19_11]],
        })
    }

    fn components(&self) -> [(u16, &[u8]); C63_PUBLIC_ARGUMENT_COMPONENTS] {
        [
            (1, &self.correction_opening),
            (2, &self.d22_whir[0][0]),
            (3, &self.d22_whir[0][1]),
            (4, &self.d22_whir[1][0]),
            (5, &self.d22_whir[1][1]),
            (6, &self.d19_projected_whir[0][0]),
            (7, &self.d19_projected_whir[0][1]),
            (8, &self.d19_projected_whir[1][0]),
            (9, &self.d19_projected_whir[1][1]),
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
            self.predecessor_correction_root,
            self.predecessor_encoded_sketch_root,
            self.correction_root,
            self.encoded_sketch_root,
        ]
        .contains(&[0; 32])
            || self.epoch == 0
            || self.old_len >= self.accepted_len
            || self.correction_opening.len() > C63_CORRECTION_OPENING_MAX_BYTES
        {
            return Err("C6.3 public argument metadata differs".to_owned());
        }
        let correction = C63CorrectionRowsOpeningReference::decode(
            &self.correction_opening,
            self.old_len,
            self.accepted_len,
            queried_rows,
        )?;
        if correction.encode(self.old_len, self.accepted_len, queried_rows)?
            != self.correction_opening
        {
            return Err("noncanonical C6.3 correction opening".to_owned());
        }
        for artifact in self.d22_whir.iter().flatten() {
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
        for artifact in self.d19_projected_whir.iter().flatten() {
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
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-component/v3");
    hasher.update(&kind.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn argument_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-argument/v3");
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

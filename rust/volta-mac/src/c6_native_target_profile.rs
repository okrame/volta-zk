use std::collections::HashSet;

use crate::c6_trace::{
    C6CanonicalTargetCohort, C6CanonicalTargetProfile, C6OperationPlanTopologyIdentity,
    C6TraceError,
};

pub const C6_NATIVE_TARGET_PROFILE_HEADER_BYTES: usize = 144;
pub const C6_NATIVE_TARGET_PROFILE_COHORT_BYTES: usize = 48;
pub const C6_NATIVE_TARGET_PROFILE_TARGET_BYTES: usize = 8;
pub const C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES: usize = 32;

const MAGIC: &[u8; 8] = b"C6NTO1\0\0";
const VERSION: u32 = 1;
const TRAILER_DOMAIN: &str = "volta-zk/c6.1/native-target-profile-codec/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6NativeTargetProfileEncodingCensus {
    pub cohort_count: u32,
    pub target_count: u32,
    pub header_bytes: u64,
    pub cohort_bytes: u64,
    pub target_bytes: u64,
    pub trailer_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6NativeTargetProfileArtifact {
    bytes: Vec<u8>,
    census: C6NativeTargetProfileEncodingCensus,
}

impl C6NativeTargetProfileArtifact {
    pub fn encode(
        profile: &C6CanonicalTargetProfile,
        topology: C6OperationPlanTopologyIdentity,
    ) -> Result<Self, C6TraceError> {
        validate_profile(profile, topology)?;
        let census = encoding_census(profile.cohorts.len(), profile.target_count())?;
        let payload_bytes = census
            .cohort_bytes
            .checked_add(census.target_bytes)
            .ok_or_else(|| C6TraceError::new("C6NTO1 payload length overflows"))?;
        let payload_bytes_u32 = u32::try_from(payload_bytes)
            .map_err(|_| C6TraceError::new("C6NTO1 payload exceeds u32"))?;
        let capacity = usize::try_from(census.total_bytes)
            .map_err(|_| C6TraceError::new("C6NTO1 artifact exceeds usize"))?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(C6_NATIVE_TARGET_PROFILE_HEADER_BYTES as u64).to_le_bytes());
        bytes.extend_from_slice(&census.total_bytes.to_le_bytes());
        bytes.extend_from_slice(&profile.topology_digest);
        bytes.extend_from_slice(&profile.source_schedule_digest);
        bytes.extend_from_slice(&profile.inference_profile_digest);
        bytes.extend_from_slice(&census.cohort_count.to_le_bytes());
        bytes.extend_from_slice(&census.target_count.to_le_bytes());
        bytes.extend_from_slice(&payload_bytes_u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        debug_assert_eq!(bytes.len(), C6_NATIVE_TARGET_PROFILE_HEADER_BYTES);

        let mut first_target = 0u32;
        for cohort in &profile.cohorts {
            let target_count = u32::try_from(cohort.canonical_nodes.len())
                .map_err(|_| C6TraceError::new("C6NTO1 cohort target count exceeds u32"))?;
            bytes.extend_from_slice(&cohort.cohort_id.to_le_bytes());
            bytes.extend_from_slice(&cohort.chain_slot.to_le_bytes());
            bytes.push(cohort.polynomial_log2);
            bytes.push(0);
            bytes.extend_from_slice(&first_target.to_le_bytes());
            bytes.extend_from_slice(&target_count.to_le_bytes());
            bytes.extend_from_slice(&cohort.claim_layout_digest);
            first_target = first_target
                .checked_add(target_count)
                .ok_or_else(|| C6TraceError::new("C6NTO1 target ordinal overflows"))?;
        }
        for cohort in &profile.cohorts {
            for (ordinal, &node) in cohort.canonical_nodes.iter().enumerate() {
                bytes.extend_from_slice(&node.to_le_bytes());
                bytes.extend_from_slice(
                    &u32::try_from(ordinal)
                        .map_err(|_| C6TraceError::new("C6NTO1 claim ordinal exceeds u32"))?
                        .to_le_bytes(),
                );
            }
        }
        let trailer = canonical_trailer(&bytes);
        bytes.extend_from_slice(&trailer);
        if bytes.len() != capacity {
            return Err(C6TraceError::new("C6NTO1 encoded length changed"));
        }
        Ok(Self { bytes, census })
    }

    pub fn decode(
        bytes: &[u8],
        topology: C6OperationPlanTopologyIdentity,
    ) -> Result<(Self, C6CanonicalTargetProfile), C6TraceError> {
        if bytes.len()
            < C6_NATIVE_TARGET_PROFILE_HEADER_BYTES + C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES
        {
            return Err(C6TraceError::new("C6NTO1 artifact is truncated"));
        }
        let trailer_start = bytes.len() - C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES;
        if canonical_trailer(&bytes[..trailer_start]) != bytes[trailer_start..] {
            return Err(C6TraceError::new("C6NTO1 canonical trailer differs"));
        }

        let mut cursor = 0usize;
        if &take::<8>(bytes, &mut cursor)? != MAGIC {
            return Err(C6TraceError::new("C6NTO1 magic differs"));
        }
        if read_u32(bytes, &mut cursor)? != VERSION {
            return Err(C6TraceError::new("C6NTO1 version differs"));
        }
        if read_u32(bytes, &mut cursor)? != 0 {
            return Err(C6TraceError::new("C6NTO1 flags are nonzero"));
        }
        if read_u64(bytes, &mut cursor)? != C6_NATIVE_TARGET_PROFILE_HEADER_BYTES as u64 {
            return Err(C6TraceError::new("C6NTO1 header length differs"));
        }
        if read_u64(bytes, &mut cursor)?
            != u64::try_from(bytes.len())
                .map_err(|_| C6TraceError::new("C6NTO1 input length exceeds u64"))?
        {
            return Err(C6TraceError::new("C6NTO1 total length differs"));
        }
        let topology_digest = take::<32>(bytes, &mut cursor)?;
        let source_schedule_digest = take::<32>(bytes, &mut cursor)?;
        let inference_profile_digest = take::<32>(bytes, &mut cursor)?;
        let cohort_count = read_u32(bytes, &mut cursor)?;
        let target_count = read_u32(bytes, &mut cursor)?;
        let payload_bytes = read_u32(bytes, &mut cursor)?;
        if read_u32(bytes, &mut cursor)? != 0 {
            return Err(C6TraceError::new("C6NTO1 reserved word is nonzero"));
        }
        if cursor != C6_NATIVE_TARGET_PROFILE_HEADER_BYTES {
            return Err(C6TraceError::new("C6NTO1 header cursor differs"));
        }
        let census = encoding_census(cohort_count as usize, target_count as usize)?;
        let expected_payload = census
            .cohort_bytes
            .checked_add(census.target_bytes)
            .ok_or_else(|| C6TraceError::new("C6NTO1 payload length overflows"))?;
        if u64::from(payload_bytes) != expected_payload || census.total_bytes != bytes.len() as u64
        {
            return Err(C6TraceError::new("C6NTO1 payload census differs"));
        }

        struct CohortHeader {
            cohort_id: u32,
            chain_slot: u16,
            polynomial_log2: u8,
            first_target: u32,
            target_count: u32,
            claim_layout_digest: [u8; 32],
        }
        let mut headers = Vec::with_capacity(cohort_count as usize);
        for _ in 0..cohort_count {
            let cohort_id = read_u32(bytes, &mut cursor)?;
            let chain_slot = read_u16(bytes, &mut cursor)?;
            let polynomial_log2 = take::<1>(bytes, &mut cursor)?[0];
            if take::<1>(bytes, &mut cursor)?[0] != 0 {
                return Err(C6TraceError::new("C6NTO1 cohort reserved byte is nonzero"));
            }
            headers.push(CohortHeader {
                cohort_id,
                chain_slot,
                polynomial_log2,
                first_target: read_u32(bytes, &mut cursor)?,
                target_count: read_u32(bytes, &mut cursor)?,
                claim_layout_digest: take::<32>(bytes, &mut cursor)?,
            });
        }
        let mut cohorts = Vec::with_capacity(headers.len());
        let mut next_target = 0u32;
        let mut seen_nodes = HashSet::with_capacity(target_count as usize);
        for header in headers {
            if header.first_target != next_target || header.target_count == 0 {
                return Err(C6TraceError::new("C6NTO1 cohort target range is noncanonical"));
            }
            let mut canonical_nodes = Vec::with_capacity(header.target_count as usize);
            for expected_ordinal in 0..header.target_count {
                let node = read_u32(bytes, &mut cursor)?;
                if read_u32(bytes, &mut cursor)? != expected_ordinal {
                    return Err(C6TraceError::new("C6NTO1 claim ordinal is noncanonical"));
                }
                if !seen_nodes.insert(node) {
                    return Err(C6TraceError::new("C6NTO1 canonical node is duplicated"));
                }
                canonical_nodes.push(node);
            }
            next_target = next_target
                .checked_add(header.target_count)
                .ok_or_else(|| C6TraceError::new("C6NTO1 target ordinal overflows"))?;
            cohorts.push(C6CanonicalTargetCohort {
                cohort_id: header.cohort_id,
                chain_slot: header.chain_slot,
                polynomial_log2: header.polynomial_log2,
                claim_layout_digest: header.claim_layout_digest,
                canonical_nodes,
            });
        }
        if next_target != target_count || cursor != trailer_start {
            return Err(C6TraceError::new("C6NTO1 target payload length differs"));
        }
        let profile = C6CanonicalTargetProfile {
            inference_profile_digest,
            topology_digest,
            source_schedule_digest,
            cohorts,
        };
        validate_profile(&profile, topology)?;
        Ok((Self { bytes: bytes.to_vec(), census }, profile))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn census(&self) -> C6NativeTargetProfileEncodingCensus {
        self.census
    }
}

fn validate_profile(
    profile: &C6CanonicalTargetProfile,
    topology: C6OperationPlanTopologyIdentity,
) -> Result<(), C6TraceError> {
    if profile.topology_digest != topology.topology_digest
        || profile.source_schedule_digest != topology.source_schedule_digest
    {
        return Err(C6TraceError::new("C6NTO1 topology binding differs"));
    }
    if profile.inference_profile_digest == [0; 32] || profile.cohorts.len() < 2 {
        return Err(C6TraceError::new("C6NTO1 inference profile is invalid"));
    }
    let mut previous_id = None;
    let mut previous_slot = None;
    let mut seen_nodes = HashSet::with_capacity(profile.target_count());
    for cohort in &profile.cohorts {
        if cohort.cohort_id == 0
            || cohort.chain_slot == 0
            || !(4..=28).contains(&cohort.polynomial_log2)
            || cohort.claim_layout_digest == [0; 32]
            || cohort.canonical_nodes.is_empty()
            || previous_id.is_some_and(|id| cohort.cohort_id <= id)
            || previous_slot.is_some_and(|slot| cohort.chain_slot <= slot)
        {
            return Err(C6TraceError::new("C6NTO1 cohort metadata is noncanonical"));
        }
        for &node in &cohort.canonical_nodes {
            if node >= topology.canonical_node_count || !seen_nodes.insert(node) {
                return Err(C6TraceError::new("C6NTO1 target node is invalid"));
            }
        }
        previous_id = Some(cohort.cohort_id);
        previous_slot = Some(cohort.chain_slot);
    }
    Ok(())
}

fn encoding_census(
    cohort_count: usize,
    target_count: usize,
) -> Result<C6NativeTargetProfileEncodingCensus, C6TraceError> {
    let cohort_count = u32::try_from(cohort_count)
        .map_err(|_| C6TraceError::new("C6NTO1 cohort count exceeds u32"))?;
    let target_count = u32::try_from(target_count)
        .map_err(|_| C6TraceError::new("C6NTO1 target count exceeds u32"))?;
    let cohort_bytes = u64::from(cohort_count)
        .checked_mul(C6_NATIVE_TARGET_PROFILE_COHORT_BYTES as u64)
        .ok_or_else(|| C6TraceError::new("C6NTO1 cohort bytes overflow"))?;
    let target_bytes = u64::from(target_count)
        .checked_mul(C6_NATIVE_TARGET_PROFILE_TARGET_BYTES as u64)
        .ok_or_else(|| C6TraceError::new("C6NTO1 target bytes overflow"))?;
    let total_bytes = (C6_NATIVE_TARGET_PROFILE_HEADER_BYTES as u64)
        .checked_add(cohort_bytes)
        .and_then(|value| value.checked_add(target_bytes))
        .and_then(|value| value.checked_add(C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES as u64))
        .ok_or_else(|| C6TraceError::new("C6NTO1 total bytes overflow"))?;
    Ok(C6NativeTargetProfileEncodingCensus {
        cohort_count,
        target_count,
        header_bytes: C6_NATIVE_TARGET_PROFILE_HEADER_BYTES as u64,
        cohort_bytes,
        target_bytes,
        trailer_bytes: C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES as u64,
        total_bytes,
    })
}

fn canonical_trailer(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TRAILER_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], C6TraceError> {
    let end = cursor.checked_add(N).ok_or_else(|| C6TraceError::new("C6NTO1 cursor overflows"))?;
    let value =
        bytes.get(*cursor..end).ok_or_else(|| C6TraceError::new("C6NTO1 artifact is truncated"))?;
    *cursor = end;
    value.try_into().map_err(|_| C6TraceError::new("C6NTO1 field length differs"))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, C6TraceError> {
    Ok(u16::from_le_bytes(take(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, C6TraceError> {
    Ok(u32::from_le_bytes(take(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, C6TraceError> {
    Ok(u64::from_le_bytes(take(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> C6OperationPlanTopologyIdentity {
        C6OperationPlanTopologyIdentity {
            version: 2,
            source_count: 7,
            source_schedule_digest: [0x31; 32],
            canonical_node_count: 256,
            public_input_count: 2,
            scalar_input_count: 3,
            product_closure_count: 4,
            product_triple_count: 5,
            zero_root_count: 6,
            topology_digest: [0x32; 32],
        }
    }

    fn profile() -> C6CanonicalTargetProfile {
        C6CanonicalTargetProfile {
            inference_profile_digest: [0x33; 32],
            topology_digest: [0x32; 32],
            source_schedule_digest: [0x31; 32],
            cohorts: vec![
                C6CanonicalTargetCohort {
                    cohort_id: 4,
                    chain_slot: 2,
                    polynomial_log2: 12,
                    claim_layout_digest: [0x34; 32],
                    canonical_nodes: vec![11, 17, 23],
                },
                C6CanonicalTargetCohort {
                    cohort_id: 9,
                    chain_slot: 7,
                    polynomial_log2: 9,
                    claim_layout_digest: [0x35; 32],
                    canonical_nodes: vec![29, 31],
                },
            ],
        }
    }

    fn reseal(bytes: &mut [u8]) {
        let trailer = bytes.len() - C6_NATIVE_TARGET_PROFILE_TRAILER_BYTES;
        let digest = canonical_trailer(&bytes[..trailer]);
        bytes[trailer..].copy_from_slice(&digest);
    }

    #[test]
    fn generic_profile_round_trips_canonically() {
        let expected = profile();
        let artifact = C6NativeTargetProfileArtifact::encode(&expected, topology()).unwrap();
        let (decoded_artifact, decoded) =
            C6NativeTargetProfileArtifact::decode(artifact.as_bytes(), topology()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded_artifact, artifact);
        assert_eq!(artifact.census().cohort_count, 2);
        assert_eq!(artifact.census().target_count, 5);
        assert_eq!(artifact.census().total_bytes, 312);
    }

    #[test]
    fn registered_two_cohort_102_target_allocation_is_exact() {
        let census = encoding_census(2, 102).unwrap();
        assert_eq!(census.header_bytes, 144);
        assert_eq!(census.cohort_bytes, 96);
        assert_eq!(census.target_bytes, 816);
        assert_eq!(census.trailer_bytes, 32);
        assert_eq!(census.total_bytes, 1_088);
        assert_eq!(309_192 + 5_320_386 + census.total_bytes, 5_630_666);
        assert!(5_630_666 < 8_000_000);
    }

    #[test]
    fn mutations_fail_closed_even_when_resealed() {
        let artifact = C6NativeTargetProfileArtifact::encode(&profile(), topology()).unwrap();
        let original = artifact.as_bytes();
        for offset in [0usize, 12, 140] {
            let mut changed = original.to_vec();
            changed[offset] ^= 1;
            reseal(&mut changed);
            assert!(C6NativeTargetProfileArtifact::decode(&changed, topology()).is_err());
        }

        let first_cohort = C6_NATIVE_TARGET_PROFILE_HEADER_BYTES;
        let first_target = first_cohort + 2 * C6_NATIVE_TARGET_PROFILE_COHORT_BYTES;
        let mut bad_range = original.to_vec();
        bad_range[first_cohort + 8] = 1;
        reseal(&mut bad_range);
        assert!(C6NativeTargetProfileArtifact::decode(&bad_range, topology()).is_err());

        let mut bad_ordinal = original.to_vec();
        bad_ordinal[first_target + 4] = 1;
        reseal(&mut bad_ordinal);
        assert!(C6NativeTargetProfileArtifact::decode(&bad_ordinal, topology()).is_err());

        let mut duplicate_node = original.to_vec();
        duplicate_node[first_target + 8..first_target + 12].copy_from_slice(&11u32.to_le_bytes());
        reseal(&mut duplicate_node);
        assert!(C6NativeTargetProfileArtifact::decode(&duplicate_node, topology()).is_err());

        let second_cohort = first_cohort + C6_NATIVE_TARGET_PROFILE_COHORT_BYTES;
        let mut duplicate_cohort = original.to_vec();
        duplicate_cohort[second_cohort..second_cohort + 4].copy_from_slice(&4u32.to_le_bytes());
        reseal(&mut duplicate_cohort);
        assert!(C6NativeTargetProfileArtifact::decode(&duplicate_cohort, topology()).is_err());

        let mut duplicate_slot = original.to_vec();
        duplicate_slot[second_cohort + 4..second_cohort + 6].copy_from_slice(&2u16.to_le_bytes());
        reseal(&mut duplicate_slot);
        assert!(C6NativeTargetProfileArtifact::decode(&duplicate_slot, topology()).is_err());

        let mut zero_profile = original.to_vec();
        zero_profile[96..128].fill(0);
        reseal(&mut zero_profile);
        assert!(C6NativeTargetProfileArtifact::decode(&zero_profile, topology()).is_err());

        let mut corrupted = original.to_vec();
        corrupted[32] ^= 1;
        assert!(C6NativeTargetProfileArtifact::decode(&corrupted, topology()).is_err());
        assert!(C6NativeTargetProfileArtifact::decode(&original[..original.len() - 1], topology())
            .is_err());
    }
}

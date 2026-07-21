//! Schema-4 manifest commitment and inclusion verification.
//!
//! The leaf/node bodies retain the frozen schema-3 widths, while every
//! envelope and hash invocation is schema-4 and `/v4` domain separated.
//! Repeated model-global cohort roots remain explicit leaf data.

use std::collections::{BTreeMap, BTreeSet};

use super::frame::{Digest, ManifestLeafFrame, ManifestNodeFrame};
use super::frame_v4::{
    hash_manifest_leaf_v4, hash_manifest_node_v4, manifest_id_digest_v4, ManifestFrameV4,
    ResponseEnvelopeFrameV4,
};
use super::manifest::ManifestError;

const MANIFEST_PADDING_DESCRIPTOR_V4: Digest = [0; 32];

#[derive(Clone, Debug)]
pub struct ManifestTreeV4 {
    manifest_id: Digest,
    real_leaves: Vec<ManifestLeafFrame>,
    levels: Vec<Vec<Digest>>,
}

impl ManifestTreeV4 {
    pub fn build(
        manifest_id: Digest,
        ordered_leaves: Vec<ManifestLeafFrame>,
    ) -> Result<Self, ManifestError> {
        if ordered_leaves.is_empty() {
            return Err(ManifestError::InvalidGeometry("empty v4 manifest"));
        }
        let mut seen = BTreeSet::new();
        let mut leaf_hashes = Vec::with_capacity(ordered_leaves.len().next_power_of_two());
        for leaf in &ordered_leaves {
            leaf.validate()?;
            if leaf.descriptor_digest == MANIFEST_PADDING_DESCRIPTOR_V4
                || !seen.insert(leaf.descriptor_digest)
            {
                return Err(ManifestError::InvalidGeometry("v4 manifest descriptor order"));
            }
            leaf_hashes.push(hash_manifest_leaf_v4(leaf)?);
        }
        let padded_len = ordered_leaves.len().next_power_of_two();
        let padding = hash_manifest_leaf_v4(&ManifestLeafFrame {
            descriptor_digest: MANIFEST_PADDING_DESCRIPTOR_V4,
            ordered_roots: vec![manifest_id, MANIFEST_PADDING_DESCRIPTOR_V4],
        })?;
        leaf_hashes.resize(padded_len, padding);
        let levels = build_levels_v4(manifest_id, leaf_hashes)?;
        Ok(Self { manifest_id, real_leaves: ordered_leaves, levels })
    }

    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0]
    }

    pub fn ordered_descriptor_digests(&self) -> Vec<Digest> {
        self.real_leaves.iter().map(|leaf| leaf.descriptor_digest).collect()
    }

    pub fn open(
        &self,
        touched_descriptors: &[Digest],
    ) -> Result<Vec<ManifestFrameV4>, ManifestError> {
        if touched_descriptors.is_empty() {
            return Err(ManifestError::InvalidProof("empty v4 manifest opening"));
        }
        let position_by_descriptor: BTreeMap<_, _> = self
            .real_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| (leaf.descriptor_digest, index))
            .collect();
        let mut positions = Vec::with_capacity(touched_descriptors.len());
        for descriptor in touched_descriptors {
            positions.push(
                *position_by_descriptor
                    .get(descriptor)
                    .ok_or(ManifestError::InvalidProof("unknown v4 manifest descriptor"))?,
            );
        }
        if !positions.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ManifestError::InvalidProof("v4 manifest descriptor order"));
        }

        let mut frames = positions
            .iter()
            .map(|position| ManifestFrameV4::Leaf(self.real_leaves[*position].clone()))
            .collect::<Vec<_>>();
        let mut nodes = BTreeSet::new();
        for mut position in positions {
            for level in 1..self.levels.len() {
                let node_index = position / 2;
                nodes.insert((level, node_index));
                position = node_index;
            }
        }
        for (level, node_index) in nodes {
            let children = &self.levels[level - 1];
            frames.push(ManifestFrameV4::Node(ManifestNodeFrame {
                manifest_id_digest: self.manifest_id,
                level: u8::try_from(level).map_err(|_| ManifestError::Overflow)?,
                node_index: u64::try_from(node_index).map_err(|_| ManifestError::Overflow)?,
                left_digest: children[2 * node_index],
                right_digest: children[2 * node_index + 1],
            }));
        }
        Ok(frames)
    }
}

fn build_levels_v4(
    manifest_id: Digest,
    leaves: Vec<Digest>,
) -> Result<Vec<Vec<Digest>>, ManifestError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(ManifestError::InvalidGeometry("v4 manifest leaf count"));
    }
    let mut levels = vec![leaves];
    let mut level = 1u8;
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity(previous.len() / 2);
        for (node_index, pair) in previous.chunks_exact(2).enumerate() {
            next.push(hash_manifest_node_v4(&ManifestNodeFrame {
                manifest_id_digest: manifest_id,
                level,
                node_index: u64::try_from(node_index).map_err(|_| ManifestError::Overflow)?,
                left_digest: pair[0],
                right_digest: pair[1],
            })?);
        }
        levels.push(next);
        level = level.checked_add(1).ok_or(ManifestError::Overflow)?;
    }
    Ok(levels)
}

pub fn verify_response_manifest_v4(
    response: &ResponseEnvelopeFrameV4,
    model_config_digest: Digest,
    weights_digest: Digest,
    ordered_full_descriptor_digests: &[Digest],
) -> Result<(), ManifestError> {
    response.validate()?;
    if ordered_full_descriptor_digests.is_empty()
        || ordered_full_descriptor_digests.iter().copied().collect::<BTreeSet<_>>().len()
            != ordered_full_descriptor_digests.len()
    {
        return Err(ManifestError::InvalidGeometry("full v4 manifest descriptors"));
    }
    let position_by_descriptor: BTreeMap<_, _> = ordered_full_descriptor_digests
        .iter()
        .copied()
        .enumerate()
        .map(|(index, descriptor)| (descriptor, index))
        .collect();
    let mut touched_positions = Vec::with_capacity(response.descriptor_digests.len());
    for descriptor in &response.descriptor_digests {
        touched_positions.push(
            *position_by_descriptor
                .get(descriptor)
                .ok_or(ManifestError::InvalidProof("response v4 manifest descriptor"))?,
        );
    }
    if !touched_positions.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ManifestError::InvalidProof("response v4 manifest order"));
    }
    let expected_depth = ordered_full_descriptor_digests.len().next_power_of_two().ilog2() as u8;
    let expected_manifest_id =
        manifest_id_digest_v4(model_config_digest, weights_digest, response.epoch);
    let touched_count = response.descriptor_digests.len();
    if response.manifest_frames.len() < touched_count {
        return Err(ManifestError::InvalidProof("v4 manifest leaf frames"));
    }

    let mut leaf_hashes = Vec::with_capacity(touched_count);
    for ((frame, expected_descriptor), position) in response.manifest_frames[..touched_count]
        .iter()
        .zip(&response.descriptor_digests)
        .zip(&touched_positions)
    {
        let ManifestFrameV4::Leaf(leaf) = frame else {
            return Err(ManifestError::InvalidProof("v4 manifest leaf order"));
        };
        if leaf.descriptor_digest != *expected_descriptor || leaf.ordered_roots.len() != 2 {
            return Err(ManifestError::InvalidProof("v4 manifest leaf statement"));
        }
        leaf_hashes.push((*position, hash_manifest_leaf_v4(leaf)?));
    }

    let mut nodes = BTreeMap::new();
    let mut previous = None;
    for frame in &response.manifest_frames[touched_count..] {
        let ManifestFrameV4::Node(node) = frame else {
            return Err(ManifestError::InvalidProof("v4 manifest node order"));
        };
        node.validate()?;
        let key = (node.level, node.node_index);
        if previous.is_some_and(|prior| prior >= key)
            || node.manifest_id_digest != expected_manifest_id
            || node.level > expected_depth
            || node.node_index
                >= 1u64
                    .checked_shl(u32::from(expected_depth - node.level))
                    .ok_or(ManifestError::Overflow)?
            || nodes.insert(key, node).is_some()
        {
            return Err(ManifestError::InvalidProof("v4 manifest node schedule"));
        }
        previous = Some(key);
    }

    let mut consumed = BTreeSet::new();
    for (mut position, mut digest) in leaf_hashes {
        for level in 1..=expected_depth {
            let node_index = u64::try_from(position / 2).map_err(|_| ManifestError::Overflow)?;
            let key = (level, node_index);
            let node =
                nodes.get(&key).ok_or(ManifestError::InvalidProof("missing v4 manifest node"))?;
            let expected_child =
                if position & 1 == 0 { node.left_digest } else { node.right_digest };
            if digest != expected_child {
                return Err(ManifestError::InvalidProof("v4 manifest child digest"));
            }
            consumed.insert(key);
            digest = hash_manifest_node_v4(node)?;
            position /= 2;
        }
        if digest != response.model_root {
            return Err(ManifestError::InvalidProof("v4 manifest model root"));
        }
    }
    if consumed.len() != nodes.len() {
        return Err(ManifestError::InvalidProof("unused v4 manifest node"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_manifest_uses_model_global_roots_and_v4_domains() {
        let model_config = [0x11; 32];
        let weights = [0x22; 32];
        let epoch = 7;
        let id = manifest_id_digest_v4(model_config, weights, epoch);
        let repeated_weight_root = [0x44; 32];
        let repeated_aux_root = [0x55; 32];
        let leaves = (0..5)
            .map(|index| ManifestLeafFrame {
                descriptor_digest: [index + 1; 32],
                ordered_roots: vec![repeated_weight_root, repeated_aux_root],
            })
            .collect::<Vec<_>>();
        let tree = ManifestTreeV4::build(id, leaves).unwrap();
        let all = tree.ordered_descriptor_digests();
        let opening = tree.open(&[all[0], all[1], all[4]]).unwrap();
        assert_eq!(opening.len(), 3 + 5);
        assert_ne!(id, super::super::frame::manifest_id_digest(model_config, weights, epoch));

        let mut reversed = vec![all[4], all[0]];
        assert!(tree.open(&reversed).is_err());
        reversed.sort();
        let unknown = [0xEE; 32];
        assert!(tree.open(&[unknown]).is_err());
    }
}

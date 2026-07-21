//! Canonical manifest commitment and inclusion proofs for X4 v3.
//!
//! The ordered full descriptor list is verifier statement data.  Responses
//! carry leaves only for touched descriptors plus the deduplicated ancestor
//! node frames needed to reach the fixed model root.  No path position or
//! depth is accepted from the prover.

use std::collections::{BTreeMap, BTreeSet};

use super::frame::{
    hash_manifest_leaf, hash_manifest_node, manifest_id_digest, Digest, FrameError, ManifestFrame,
    ManifestLeafFrame, ManifestNodeFrame, ResponseEnvelopeFrame,
};

const MANIFEST_PADDING_DESCRIPTOR: Digest = [0; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    Frame(FrameError),
    InvalidGeometry(&'static str),
    InvalidProof(&'static str),
    Overflow,
}

impl From<FrameError> for ManifestError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

#[derive(Clone, Debug)]
pub struct ManifestTree {
    manifest_id: Digest,
    real_leaves: Vec<ManifestLeafFrame>,
    levels: Vec<Vec<Digest>>,
}

impl ManifestTree {
    pub fn build(
        manifest_id: Digest,
        ordered_leaves: Vec<ManifestLeafFrame>,
    ) -> Result<Self, ManifestError> {
        if ordered_leaves.is_empty() {
            return Err(ManifestError::InvalidGeometry("empty manifest"));
        }
        let mut seen = BTreeSet::new();
        let mut leaf_hashes = Vec::with_capacity(ordered_leaves.len().next_power_of_two());
        for leaf in &ordered_leaves {
            leaf.validate()?;
            if leaf.descriptor_digest == MANIFEST_PADDING_DESCRIPTOR
                || !seen.insert(leaf.descriptor_digest)
            {
                return Err(ManifestError::InvalidGeometry("manifest descriptor order"));
            }
            leaf_hashes.push(hash_manifest_leaf(leaf)?);
        }
        let padded_len = ordered_leaves.len().next_power_of_two();
        let padding = hash_manifest_leaf(&ManifestLeafFrame {
            descriptor_digest: MANIFEST_PADDING_DESCRIPTOR,
            ordered_roots: vec![manifest_id, MANIFEST_PADDING_DESCRIPTOR],
        })?;
        leaf_hashes.resize(padded_len, padding);
        let levels = build_levels(manifest_id, leaf_hashes)?;
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
    ) -> Result<Vec<ManifestFrame>, ManifestError> {
        if touched_descriptors.is_empty() {
            return Err(ManifestError::InvalidProof("empty manifest opening"));
        }
        let position_by_descriptor: BTreeMap<_, _> = self
            .real_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| (leaf.descriptor_digest, index))
            .collect();
        let mut positions = Vec::with_capacity(touched_descriptors.len());
        for descriptor in touched_descriptors {
            let position = *position_by_descriptor
                .get(descriptor)
                .ok_or(ManifestError::InvalidProof("unknown manifest descriptor"))?;
            positions.push(position);
        }
        if !positions.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ManifestError::InvalidProof("manifest descriptor order"));
        }

        let mut frames = Vec::new();
        for position in &positions {
            frames.push(ManifestFrame::Leaf(self.real_leaves[*position].clone()));
        }
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
            frames.push(ManifestFrame::Node(ManifestNodeFrame {
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

fn build_levels(
    manifest_id: Digest,
    leaves: Vec<Digest>,
) -> Result<Vec<Vec<Digest>>, ManifestError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(ManifestError::InvalidGeometry("manifest leaf count"));
    }
    let mut levels = vec![leaves];
    let mut level = 1u8;
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity(previous.len() / 2);
        for (node_index, pair) in previous.chunks_exact(2).enumerate() {
            next.push(hash_manifest_node(&ManifestNodeFrame {
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

pub fn verify_response_manifest(
    response: &ResponseEnvelopeFrame,
    model_config_digest: Digest,
    weights_digest: Digest,
    ordered_full_descriptor_digests: &[Digest],
) -> Result<(), ManifestError> {
    response.validate()?;
    if ordered_full_descriptor_digests.is_empty()
        || ordered_full_descriptor_digests.iter().copied().collect::<BTreeSet<_>>().len()
            != ordered_full_descriptor_digests.len()
    {
        return Err(ManifestError::InvalidGeometry("full manifest descriptors"));
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
                .ok_or(ManifestError::InvalidProof("response manifest descriptor"))?,
        );
    }
    if !touched_positions.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ManifestError::InvalidProof("response manifest order"));
    }
    let expected_depth = ordered_full_descriptor_digests.len().next_power_of_two().ilog2() as u8;
    let expected_manifest_id =
        manifest_id_digest(model_config_digest, weights_digest, response.epoch);

    let touched_count = response.descriptor_digests.len();
    if response.manifest_frames.len() < touched_count {
        return Err(ManifestError::InvalidProof("manifest leaf frames"));
    }
    let mut leaf_hashes = Vec::with_capacity(touched_count);
    for ((frame, expected_descriptor), position) in response.manifest_frames[..touched_count]
        .iter()
        .zip(&response.descriptor_digests)
        .zip(&touched_positions)
    {
        let ManifestFrame::Leaf(leaf) = frame else {
            return Err(ManifestError::InvalidProof("manifest leaf order"));
        };
        if leaf.descriptor_digest != *expected_descriptor || leaf.ordered_roots.len() != 2 {
            return Err(ManifestError::InvalidProof("manifest leaf statement"));
        }
        leaf_hashes.push((*position, hash_manifest_leaf(leaf)?));
    }

    let mut nodes = BTreeMap::new();
    let mut previous = None;
    for frame in &response.manifest_frames[touched_count..] {
        let ManifestFrame::Node(node) = frame else {
            return Err(ManifestError::InvalidProof("manifest node order"));
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
            return Err(ManifestError::InvalidProof("manifest node schedule"));
        }
        previous = Some(key);
    }

    let mut consumed = BTreeSet::new();
    for (mut position, mut digest) in leaf_hashes {
        for level in 1..=expected_depth {
            let node_index = u64::try_from(position / 2).map_err(|_| ManifestError::Overflow)?;
            let key = (level, node_index);
            let node =
                nodes.get(&key).ok_or(ManifestError::InvalidProof("missing manifest node"))?;
            let expected_child =
                if position & 1 == 0 { node.left_digest } else { node.right_digest };
            if digest != expected_child {
                return Err(ManifestError::InvalidProof("manifest child digest"));
            }
            consumed.insert(key);
            digest = hash_manifest_node(node)?;
            position /= 2;
        }
        if digest != response.model_root {
            return Err(ManifestError::InvalidProof("manifest model root"));
        }
    }
    if consumed.len() != nodes.len() {
        return Err(ManifestError::InvalidProof("unused manifest node"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::frame::{
        authenticated_output_link_schedule_digest, profile_digest, AuthenticatedOutputLinkFrame,
        M9TransferFrame, ResponseZeroBatchFrame,
    };
    use volta_field::Fp2;

    fn response_for(tree: &ManifestTree, touched: &[Digest], epoch: u64) -> ResponseEnvelopeFrame {
        let h = vec![Fp2::ZERO; touched.len()];
        let m9 = touched
            .iter()
            .map(|descriptor| M9TransferFrame {
                descriptor_digest: *descriptor,
                mask_correction_symbol: Fp2::ZERO,
            })
            .collect::<Vec<_>>();
        let round_count = 2;
        let domains = [100, 101, 102, 103];
        let schedule = authenticated_output_link_schedule_digest(
            epoch,
            &[],
            touched,
            &h,
            &m9,
            round_count,
            &domains,
        )
        .unwrap();
        ResponseEnvelopeFrame {
            profile_digest: profile_digest(),
            model_root: tree.root(),
            epoch,
            descriptor_digests: touched.to_vec(),
            manifest_frames: tree.open(touched).unwrap(),
            claim_frames: vec![],
            ordered_h_symbols: h,
            m9_frames: m9,
            authenticated_output_link_frame: AuthenticatedOutputLinkFrame {
                relation_count: u16::try_from(2 * touched.len()).unwrap(),
                round_count,
                link_schedule_digest: schedule,
                ordered_round_correction_symbols: vec![Fp2::ZERO; 4],
                terminal_opened_tag_symbol: Fp2::ZERO,
            },
            fold_frames: vec![],
            query_frames: vec![],
            zero_batch_frame: ResponseZeroBatchFrame {
                claim_count: u16::try_from(touched.len()).unwrap(),
                mask_correction_symbol: Fp2::ZERO,
                opened_tag_symbol: Fp2::ZERO,
            },
        }
    }

    #[test]
    fn manifest_paths_are_deduplicated_and_verify_against_model_root() {
        let model_config = [0x11; 32];
        let weights = [0x22; 32];
        let epoch = 7;
        let id = manifest_id_digest(model_config, weights, epoch);
        let leaves = (0..5)
            .map(|index| ManifestLeafFrame {
                descriptor_digest: [index + 1; 32],
                ordered_roots: vec![[0x40 + index; 32], [0x50 + index; 32]],
            })
            .collect::<Vec<_>>();
        let tree = ManifestTree::build(id, leaves).unwrap();
        let all = tree.ordered_descriptor_digests();
        let touched = vec![all[0], all[1], all[4]];
        let response = response_for(&tree, &touched, epoch);
        verify_response_manifest(&response, model_config, weights, &all).unwrap();
        let naive_nodes = touched.len() * all.len().next_power_of_two().ilog2() as usize;
        assert!(response.manifest_frames.len() - touched.len() < naive_nodes);
    }

    #[test]
    fn every_manifest_leaf_node_type_depth_index_and_root_tamper_rejects() {
        let model_config = [0x31; 32];
        let weights = [0x32; 32];
        let epoch = 13;
        let id = manifest_id_digest(model_config, weights, epoch);
        let tree = ManifestTree::build(
            id,
            (0..4)
                .map(|index| ManifestLeafFrame {
                    descriptor_digest: [index + 1; 32],
                    ordered_roots: vec![[index + 10; 32], [index + 20; 32]],
                })
                .collect(),
        )
        .unwrap();
        let all = tree.ordered_descriptor_digests();
        let honest = response_for(&tree, &[all[1], all[2]], epoch);
        verify_response_manifest(&honest, model_config, weights, &all).unwrap();

        let mut bad = honest.clone();
        match &mut bad.manifest_frames[0] {
            ManifestFrame::Leaf(leaf) => leaf.ordered_roots[1][0] ^= 1,
            _ => unreachable!(),
        }
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());

        let node_offset = honest.descriptor_digests.len();
        let mut bad = honest.clone();
        match &mut bad.manifest_frames[node_offset] {
            ManifestFrame::Node(node) => node.left_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());

        let mut bad = honest.clone();
        match &mut bad.manifest_frames[node_offset] {
            ManifestFrame::Node(node) => node.level += 1,
            _ => unreachable!(),
        }
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());

        let mut bad = honest.clone();
        match &mut bad.manifest_frames[node_offset] {
            ManifestFrame::Node(node) => node.node_index += 1,
            _ => unreachable!(),
        }
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());

        let mut bad = honest.clone();
        bad.manifest_frames.swap(0, node_offset);
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());

        let mut bad = honest;
        bad.model_root[0] ^= 1;
        assert!(verify_response_manifest(&bad, model_config, weights, &all).is_err());
    }
}

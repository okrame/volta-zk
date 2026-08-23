//! blake3 Merkle tree over the columns of the encoded Ligero matrix.
//!
//! Leaves are unsalted: every codeword symbol already carries the per-row
//! random pad's entropy (each symbol's marginal is uniform), so leaf hashes
//! hide the weight data computationally without extra salt bytes.

use std::collections::BTreeMap;

pub type Hash = [u8; 32];

pub fn hash_leaf(bytes: &[u8]) -> Hash {
    *blake3::hash(bytes).as_bytes()
}

fn hash_pair(l: &Hash, r: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

/// Full tree kept in memory: `levels[0]` = leaf hashes, last level = [root].
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build from precomputed leaf hashes (power-of-two count).
    pub fn from_leaves(leaves: Vec<Hash>) -> MerkleTree {
        assert!(leaves.len().is_power_of_two());
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next: Vec<Hash> = prev.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Sibling path from leaf `idx` to the root.
    pub fn open(&self, idx: usize) -> Vec<Hash> {
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut i = idx;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[i ^ 1]);
            i >>= 1;
        }
        path
    }

    /// Canonical deduplicated frontier for sorted, distinct leaf indices.
    pub fn open_multi(&self, indices: &[usize]) -> Option<Vec<Hash>> {
        if indices.is_empty()
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
            || indices.last().copied()? >= self.levels[0].len()
        {
            return None;
        }
        let mut frontier = Vec::new();
        let mut current = indices.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            for &index in &current {
                let sibling = index ^ 1;
                if current.binary_search(&sibling).is_err() {
                    frontier.push(level[sibling]);
                }
            }
            current = current.into_iter().map(|index| index >> 1).collect();
            current.dedup();
        }
        Some(frontier)
    }
}

/// Verify the canonical frontier produced by [`MerkleTree::open_multi`].
pub fn verify_multi(
    root: &Hash,
    indices: &[usize],
    leaves: &[Hash],
    frontier: &[Hash],
    expected_depth: usize,
) -> bool {
    multi_root(indices, leaves, frontier, expected_depth).as_ref() == Some(root)
}

/// Reconstruct the root from a canonical multiproof frontier.
pub fn multi_root(
    indices: &[usize],
    leaves: &[Hash],
    frontier: &[Hash],
    expected_depth: usize,
) -> Option<Hash> {
    let Ok(depth) = u32::try_from(expected_depth) else {
        return None;
    };
    let Some(leaf_count) = 1usize.checked_shl(depth) else {
        return None;
    };
    if indices.is_empty()
        || indices.len() != leaves.len()
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
        || indices.last().is_some_and(|&index| index >= leaf_count)
    {
        return None;
    }

    let mut current =
        indices.iter().copied().zip(leaves.iter().copied()).collect::<BTreeMap<_, _>>();
    let mut frontier = frontier.iter();
    for _ in 0..expected_depth {
        let mut parents = BTreeMap::new();
        for (&index, &node) in &current {
            if index & 1 == 1 && current.contains_key(&(index - 1)) {
                continue;
            }
            let sibling = match current.get(&(index ^ 1)).copied() {
                Some(sibling) => sibling,
                None => match frontier.next().copied() {
                    Some(sibling) => sibling,
                    None => return None,
                },
            };
            let parent = if index & 1 == 0 {
                hash_pair(&node, &sibling)
            } else {
                hash_pair(&sibling, &node)
            };
            if parents.insert(index >> 1, parent).is_some() {
                return None;
            }
        }
        current = parents;
    }
    if frontier.next().is_none() && current.len() == 1 {
        current.get(&0).copied()
    } else {
        None
    }
}

/// Recompute the root from a leaf hash and its sibling path. The caller pins
/// the committed tree depth; accepting a shorter or longer path would verify
/// against a different tree shape.
pub fn verify_path(
    root: &Hash,
    mut idx: usize,
    leaf: Hash,
    path: &[Hash],
    expected_depth: usize,
) -> bool {
    let Ok(depth) = u32::try_from(expected_depth) else {
        return false;
    };
    let Some(leaf_count) = 1usize.checked_shl(depth) else {
        return false;
    };
    if path.len() != expected_depth || idx >= leaf_count {
        return false;
    }
    let mut acc = leaf;
    for sib in path {
        acc = if idx & 1 == 0 { hash_pair(&acc, sib) } else { hash_pair(sib, &acc) };
        idx >>= 1;
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_verify_roundtrip_and_tamper() {
        let leaves: Vec<Hash> = (0..16u8).map(|i| hash_leaf(&[i])).collect();
        let tree = MerkleTree::from_leaves(leaves.clone());
        assert_eq!(
            tree.root(),
            [
                0x45, 0x14, 0xd7, 0xcb, 0xd7, 0xa1, 0x95, 0x56, 0x08, 0x77, 0x4f, 0xf4, 0xce, 0x36,
                0x98, 0x40, 0xa4, 0xe4, 0x0e, 0x72, 0x2c, 0xaa, 0x2a, 0x8c, 0xce, 0xe2, 0xf6, 0xd0,
                0x53, 0x9d, 0x9f, 0x17,
            ],
            "verifier strictness must not change the legacy commitment root",
        );
        for idx in 0..16 {
            let path = tree.open(idx);
            assert!(verify_path(&tree.root(), idx, leaves[idx], &path, 4));
            // Wrong leaf, wrong index, tampered path all fail.
            assert!(!verify_path(&tree.root(), idx, hash_leaf(&[99]), &path, 4));
            assert!(!verify_path(&tree.root(), idx ^ 1, leaves[idx], &path, 4));
            let mut bad = path.clone();
            bad[0][0] ^= 1;
            assert!(!verify_path(&tree.root(), idx, leaves[idx], &bad, 4));

            let mut short = path.clone();
            short.pop();
            assert!(!verify_path(&tree.root(), idx, leaves[idx], &short, 4));

            let mut long = path.clone();
            long.push([0; 32]);
            assert!(!verify_path(&tree.root(), idx, leaves[idx], &long, 4));
        }
        assert!(!verify_path(&tree.root(), 16, leaves[0], &tree.open(0), 4));
    }

    #[test]
    fn multi_opening_is_canonical_and_rejects_malformed_frontiers() {
        let leaves: Vec<Hash> = (0..16u8).map(|i| hash_leaf(&[i])).collect();
        let tree = MerkleTree::from_leaves(leaves.clone());
        for indices in [vec![0], vec![2, 3, 4, 11], vec![0, 7, 8, 15]] {
            let opened = indices.iter().map(|&index| leaves[index]).collect::<Vec<_>>();
            let frontier = tree.open_multi(&indices).unwrap();
            assert!(verify_multi(&tree.root(), &indices, &opened, &frontier, 4));

            let mut bad_leaf = opened.clone();
            bad_leaf[0][0] ^= 1;
            assert!(!verify_multi(&tree.root(), &indices, &bad_leaf, &frontier, 4));
            let mut short = frontier.clone();
            short.pop();
            assert!(!verify_multi(&tree.root(), &indices, &opened, &short, 4));
            let mut long = frontier.clone();
            long.push([0; 32]);
            assert!(!verify_multi(&tree.root(), &indices, &opened, &long, 4));
        }

        assert!(tree.open_multi(&[3, 3]).is_none());
        assert!(tree.open_multi(&[4, 3]).is_none());
        assert!(tree.open_multi(&[16]).is_none());
        assert!(!verify_multi(&tree.root(), &[3, 3], &[leaves[3], leaves[3]], &[], 4));
    }
}

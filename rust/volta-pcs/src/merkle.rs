//! blake3 Merkle tree over the columns of the encoded Ligero matrix.
//!
//! Leaves are unsalted: every codeword symbol already carries the per-row
//! random pad's entropy (each symbol's marginal is uniform), so leaf hashes
//! hide the weight data computationally without extra salt bytes.

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
            let next: Vec<Hash> =
                prev.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
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
}

/// Recompute the root from a leaf hash and its sibling path.
pub fn verify_path(root: &Hash, mut idx: usize, leaf: Hash, path: &[Hash]) -> bool {
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
        for idx in 0..16 {
            let path = tree.open(idx);
            assert!(verify_path(&tree.root(), idx, leaves[idx], &path));
            // Wrong leaf, wrong index, tampered path all fail.
            assert!(!verify_path(&tree.root(), idx, hash_leaf(&[99]), &path));
            assert!(!verify_path(&tree.root(), idx ^ 1, leaves[idx], &path));
            let mut bad = path.clone();
            bad[0][0] ^= 1;
            assert!(!verify_path(&tree.root(), idx, leaves[idx], &bad));
        }
    }
}

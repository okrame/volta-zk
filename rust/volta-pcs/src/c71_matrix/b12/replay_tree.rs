//! Bounded reference Merkle replay for one B12 base-field oracle.
//!
//! This retains only the immutable row getter, the committed private-coin
//! stream, subtree salt offsets, and the tree at and above `cut` leaves.

use super::streaming::{
    digest, merge_coset, node_hash, prepare_offsets, reduce_in_place, strided_leaves_in_place,
};
use super::{Goldilocks, HidingMmcs, PrivateRng};
use p3_commit::Mmcs;
use p3_field::PrimeField64;
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use rand_010::RngExt;
use std::collections::BTreeMap;
use std::sync::Arc;

const LEAF: &[u8] = b"volta-zk/c71/b12/merkle/leaf/v1\0";
const SALTS: usize = 4;
const MAX_REFERENCE_HEIGHT: usize = 1 << 18;
pub(super) const MAX_REFERENCE_ROWS: usize = 1024;
pub(super) const CANONICAL_QUERY_ROWS: usize = 1 << 21;

pub(super) fn query_batch_rows(height: usize) -> usize {
    if height > MAX_REFERENCE_HEIGHT {
        CANONICAL_QUERY_ROWS
    } else {
        MAX_REFERENCE_ROWS
    }
}

/// Existing small reference geometry, or the selected initial W/A geometry.
/// Later large extension oracles still require their separate S1/S2 schedule.
pub(super) fn initial_geometry(height: usize, columns: usize) -> Result<(usize, usize), String> {
    if height < 16 || !height.is_power_of_two() || columns == 0 {
        return Err("initial replay geometry differs".into());
    }
    if height <= MAX_REFERENCE_HEIGHT {
        let rows = 256.min(height);
        return Ok((rows, (height / rows).max(16)));
    }
    if ![1usize << 31, 1usize << 32].contains(&height) || columns != 128 {
        return Err("large replay requires the selected initial W/A geometry".into());
    }
    Ok((1 << 22, 1 << 12))
}

type Digest = [u8; 32];
pub(super) type Commitment = MerkleCap<Goldilocks, Digest>;
pub(super) type MultiProof = <HidingMmcs as Mmcs<Goldilocks>>::MultiProof;
pub(super) type Opening = (Vec<Vec<Vec<Goldilocks>>>, MultiProof);
pub(super) type Rows = Arc<dyn Fn(&[usize]) -> Result<Vec<Vec<Goldilocks>>, String> + Send + Sync>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ReplayWork {
    pub leaf_hashes: u64,
    pub node_hashes: u64,
    pub salt_candidate_bytes: u64,
    pub coset_cells: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ReplayMemory {
    pub retained_digest_bytes: usize,
    pub salt_offset_bytes: usize,
    pub rng_snapshot_bytes: usize,
    pub peak_coset_bytes: usize,
    // Merkle-only subtotal, excluding the source/FFT callback, top cache and
    // other live owners. This is not a complete simultaneous physical peak.
    pub peak_commit_scratch_bytes: usize,
    pub open_subtree_bytes_each: usize,
}

pub(super) struct Tree {
    height: usize,
    base_columns: usize,
    coset_rows: usize,
    cosets: usize,
    cut: usize,
    row: Rows,
    private_stream: PrivateRng,
    subtree_offsets: Vec<u64>,
    // Level zero contains roots of `cut`-leaf subtrees; the last level is root.
    top: Vec<Vec<Digest>>,
    pub work: ReplayWork,
    pub memory: ReplayMemory,
}

impl Tree {
    pub(super) fn commit(
        mmcs: &HidingMmcs,
        height: usize,
        base_columns: usize,
        coset_rows: usize,
        cut: usize,
        coset: impl Fn(usize) -> Result<Vec<u64>, String>,
        row: Rows,
    ) -> Result<(Commitment, Self), String> {
        if height < 16
            || !height.is_power_of_two()
            || coset_rows == 0
            || !coset_rows.is_power_of_two()
            || height % coset_rows != 0
            || base_columns == 0
        {
            return Err("replay tree geometry differs".into());
        }
        if height > MAX_REFERENCE_HEIGHT
            && initial_geometry(height, base_columns)? != (coset_rows, cut)
        {
            return Err("canonical initial replay schedule differs".into());
        }
        let cosets = height / coset_rows;
        if !cosets.is_power_of_two() || !cut.is_power_of_two() || cut < cosets || cut > height {
            return Err("replay coset count differs".into());
        }
        let physical_columns = base_columns.max(4);
        let mut starts = vec![0; coset_rows];
        let mut subtree_offsets = vec![0; height / cut];
        let (private_stream, prescan_bytes) = mmcs.with_private_rng(|rng| {
            let snapshot = clone_stream(rng);
            let scanned = prepare_offsets(rng, cosets, &mut starts, |leaf, offset| {
                if leaf % cut == 0 {
                    subtree_offsets[leaf / cut] = offset;
                }
            });
            (snapshot, scanned)
        });
        let prescan_bytes = prescan_bytes?;

        let mut current = starts;
        let mut frontier = vec![[0; 32]; coset_rows * cosets.ilog2() as usize];
        let mut cut_roots = Vec::with_capacity(height / cut);
        let mut work = ReplayWork { salt_candidate_bytes: prescan_bytes, ..Default::default() };
        for c in 0..cosets {
            let mut cells = coset(c)?;
            if cells.len() != physical_columns * coset_rows {
                return Err("replay coset payload shape differs".into());
            }
            work.coset_cells += (base_columns * coset_rows) as u64;
            let hashed = strided_leaves_in_place(
                &mut cells,
                coset_rows,
                base_columns,
                &private_stream,
                &mut current,
            )?;
            work.leaf_hashes += coset_rows as u64;
            work.salt_candidate_bytes += hashed.salt_candidate_bytes;
            work.node_hashes +=
                merge_coset(&mut cells, coset_rows, c, cosets, &mut frontier)? as u64;
            if c + 1 == cosets {
                // The final coset already contains Q-leaf subtree roots.
                // Reduce them in their consumed cells; never duplicate L digests.
                let mut live = coset_rows;
                while live > height / cut {
                    reduce_in_place(&mut cells, coset_rows, live)?;
                    live /= 2;
                    work.node_hashes += live as u64;
                }
                cut_roots.extend((0..live).map(|j| digest(&cells, coset_rows, j)));
            }
        }

        let mut top = vec![cut_roots];
        while top.last().unwrap().len() > 1 {
            let previous = top.last().unwrap();
            let next: Vec<_> =
                previous.chunks_exact(2).map(|pair| node_hash(pair[0], pair[1])).collect();
            work.node_hashes += next.len() as u64;
            top.push(next);
        }
        let root = top.last().unwrap()[0];
        let memory = ReplayMemory {
            retained_digest_bytes: top.iter().map(|level| level.len() * 32).sum(),
            salt_offset_bytes: subtree_offsets.len() * size_of::<u64>(),
            rng_snapshot_bytes: size_of::<PrivateRng>(),
            peak_coset_bytes: physical_columns * coset_rows * size_of::<u64>(),
            peak_commit_scratch_bytes: physical_columns * coset_rows * size_of::<u64>()
                + frontier.len() * size_of::<Digest>()
                + current.len() * size_of::<u64>(),
            open_subtree_bytes_each: (2 * cut - 1) * size_of::<Digest>()
                + cut * SALTS * size_of::<Goldilocks>(),
        };
        Ok((
            MerkleCap::from(vec![root]),
            Self {
                height,
                base_columns,
                coset_rows,
                cosets,
                cut,
                row,
                private_stream,
                subtree_offsets,
                top,
                work,
                memory,
            },
        ))
    }

    pub(super) fn open(&self, indices: &[usize]) -> Result<Opening, String> {
        let batch_cap = query_batch_rows(self.height);
        if self.cut > batch_cap
            || indices.len() > MAX_REFERENCE_ROWS
            || indices.iter().any(|&index| index >= self.height)
        {
            return Err("replay opening outside domain or reference batch cap".into());
        }
        let mut needed: Vec<_> = indices.iter().map(|&i| i / self.cut).collect();
        needed.sort_unstable();
        needed.dedup();
        let mut queries: Vec<_> =
            indices.iter().enumerate().map(|(position, &index)| (index, position)).collect();
        queries.sort_unstable();
        let mut cursor = 0;
        let mut opened = vec![Vec::new(); indices.len()];
        let mut subtrees = BTreeMap::new();
        for batch in needed.chunks(batch_cap / self.cut) {
            let batch_indices: Vec<_> = batch
                .iter()
                .flat_map(|&subtree| subtree * self.cut..(subtree + 1) * self.cut)
                .collect();
            let rows = (self.row)(&batch_indices)?;
            if rows.len() != batch_indices.len()
                || rows.iter().any(|row| row.len() != self.base_columns)
            {
                return Err("replay opening row shape differs".into());
            }
            for (&subtree, values) in batch.iter().zip(rows.chunks_exact(self.cut)) {
                let start = subtree * self.cut;
                while cursor < queries.len() && queries[cursor].0 < start + self.cut {
                    let (index, position) = queries[cursor];
                    opened[position] = vec![values[index - start].clone()];
                    cursor += 1;
                }
                subtrees.insert(subtree, self.regenerate(subtree, values)?);
            }
        }

        let salts = indices
            .iter()
            .map(|&i| vec![subtrees[&(i / self.cut)].salts[i % self.cut].to_vec()])
            .collect();

        let mut frontier = indices.to_vec();
        frontier.sort_unstable();
        frontier.dedup();
        let mut siblings = Vec::new();
        for level in 0..self.height.ilog2() as usize {
            let mut parents = Vec::with_capacity(frontier.len());
            let mut i = 0;
            while i < frontier.len() {
                let parent = frontier[i] / 2;
                let left = 2 * parent;
                let right = left + 1;
                let has_left = frontier[i] == left;
                let has_right = if has_left {
                    i + 1 < frontier.len() && frontier[i + 1] == right
                } else {
                    true
                };
                if !has_left {
                    siblings.push(self.digest_at(level, left, &subtrees));
                }
                if !has_right {
                    siblings.push(self.digest_at(level, right, &subtrees));
                }
                parents.push(parent);
                i += usize::from(has_left) + usize::from(has_right);
            }
            frontier = parents;
        }
        Ok((opened, (salts, PrunedMerklePaths { sibling_hashes: siblings })))
    }

    fn regenerate(&self, subtree: usize, rows: &[Vec<Goldilocks>]) -> Result<Subtree, String> {
        let mut rng = stream_at(&self.private_stream, self.subtree_offsets[subtree])?;
        let mut salts = Vec::with_capacity(self.cut);
        let mut leaves = Vec::with_capacity(self.cut);
        if rows.len() != self.cut {
            return Err("replay subtree row count differs".into());
        }
        for values in rows {
            if values.len() != self.base_columns {
                return Err("replay row width differs".into());
            }
            let salt: [Goldilocks; SALTS] = std::array::from_fn(|_| rng.random());
            leaves.push(leaf_hash(values, &salt));
            salts.push(salt);
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| node_hash(pair[0], pair[1]))
                .collect();
            levels.push(next);
        }
        if levels.last().unwrap()[0] != self.top[0][subtree] {
            return Err("replayed subtree does not match committed cache".into());
        }
        Ok(Subtree { salts, levels })
    }

    fn digest_at(&self, level: usize, index: usize, subtrees: &BTreeMap<usize, Subtree>) -> Digest {
        let cut_log = self.cut.ilog2() as usize;
        if level < cut_log {
            let leaves_per_node = 1usize << level;
            let leaf = index * leaves_per_node;
            let subtree = leaf / self.cut;
            let local = (leaf % self.cut) / leaves_per_node;
            subtrees[&subtree].levels[level][local]
        } else {
            self.top[level - cut_log][index]
        }
    }

    pub(super) fn geometry(&self) -> (usize, usize, usize, usize) {
        (self.height, self.cosets, self.coset_rows, self.cut)
    }
}

struct Subtree {
    salts: Vec<[Goldilocks; SALTS]>,
    levels: Vec<Vec<Digest>>,
}

fn clone_stream(rng: &PrivateRng) -> PrivateRng {
    PrivateRng { reader: rng.reader.clone(), remaining: rng.remaining }
}

fn stream_at(original: &PrivateRng, offset: u64) -> Result<PrivateRng, String> {
    if offset >= 1 << 40 {
        return Err("private coin offset exhausted".into());
    }
    let mut rng = clone_stream(original);
    rng.reader.set_position(offset);
    rng.remaining = (1 << 40) - offset;
    Ok(rng)
}

fn leaf_hash(values: &[Goldilocks], salts: &[Goldilocks; SALTS]) -> Digest {
    let mut hash = blake3::Hasher::new();
    hash.update(LEAF);
    for value in values.iter().chain(salts) {
        hash.update(&value.as_canonical_u64().to_le_bytes());
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::b12::mmcs;
    use p3_matrix::dense::RowMajorMatrix;

    #[test]
    fn c71_b12_canonical_initial_geometry_selects_512_a_scans_without_allocation() {
        for (height, passes) in [(1usize << 31, 512), (1usize << 32, 1024)] {
            let (rows, cut) = initial_geometry(height, 128).unwrap();
            assert_eq!(rows, 1 << 22);
            assert_eq!(height / rows, passes);
            assert_eq!(cut, 4096);
            assert_eq!(rows * 128 * 8, 4 << 30);
            assert_eq!(query_batch_rows(height), 1 << 21);
            // The superseded A/1024 reconstruction shape is rejected before
            // salt sampling, source calls or any large allocation.
            assert!(Tree::commit(
                &mmcs([1; 32]),
                height,
                128,
                1 << 21,
                cut,
                |_| panic!("invalid schedule must not read the source"),
                Arc::new(|_| panic!("invalid schedule must not open rows"))
            )
            .is_err());
        }
        assert_eq!(query_batch_rows(1 << 18), 1024);
        assert!(initial_geometry(1 << 30, 12).is_err());
        assert!(initial_geometry(1 << 33, 128).is_err());
        assert!(initial_geometry(1 << 31, 384).is_err());
    }

    #[test]
    fn replay_tree_matches_native_root_rows_salts_and_pruned_frontier() {
        for (height, coset_rows) in [(64, 16), (2048, 256)] {
            let columns = 2;
            let values: Arc<Vec<Goldilocks>> = Arc::new(
                (0..height * columns).map(|i| Goldilocks::new((17 * i + 3) as u64)).collect(),
            );
            let native = mmcs([41; 32]);
            let matrix = RowMajorMatrix::new(values.as_ref().clone(), columns);
            let (expected_root, native_data) = native.commit_matrix(matrix);

            let replay_mmcs = mmcs([41; 32]);
            let row_values = values.clone();
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let getter_calls = calls.clone();
            let getter: Rows = Arc::new(move |indices| {
                assert!(indices.len() <= MAX_REFERENCE_ROWS);
                getter_calls.lock().unwrap().push(indices.to_vec());
                Ok(indices
                    .iter()
                    .map(|&r| row_values[r * columns..(r + 1) * columns].to_vec())
                    .collect())
            });
            let coset_values = values.clone();
            let (root, mut tree) = Tree::commit(
                &replay_mmcs,
                height,
                columns,
                coset_rows,
                16,
                move |c| {
                    let q = height / coset_rows;
                    let mut cells = vec![0; coset_rows * columns.max(4)];
                    for col in 0..columns {
                        for j in 0..coset_rows {
                            cells[col * coset_rows + j] =
                                coset_values[(c + q * j) * columns + col].as_canonical_u64();
                        }
                    }
                    Ok(cells)
                },
                getter,
            )
            .unwrap();
            assert_eq!(root, expected_root);
            assert_eq!(tree.geometry(), (height, height / coset_rows, coset_rows, 16));
            assert_eq!(tree.work.leaf_hashes, height as u64);
            assert_eq!(tree.work.node_hashes, (height - 1) as u64);
            assert!(tree.memory.retained_digest_bytes < height * 32);

            let indices = if height == 64 {
                vec![37, 2, 37, 63, 16]
            } else {
                (0..height).step_by(16).rev().chain([0, height - 1, 0]).collect()
            };
            let got = tree.open(&indices).unwrap();
            let expected = replay_mmcs.open_multi_batch(&indices, &native_data);
            assert_eq!(got.0, expected.0);
            assert_eq!(got.1 .0, expected.1 .0);
            assert_eq!(got.1 .1.sibling_hashes, expected.1 .1.sibling_hashes);
            replay_mmcs
                .verify_multi_batch(
                    &root,
                    &[p3_matrix::Dimensions { width: columns, height }],
                    &indices,
                    &got.0,
                    &got.1,
                )
                .unwrap();
            assert_eq!(calls.lock().unwrap().len(), height.div_ceil(MAX_REFERENCE_ROWS));
            assert_eq!(
                calls.lock().unwrap().iter().flatten().copied().collect::<Vec<_>>(),
                (0..height).collect::<Vec<_>>()
            );
            assert!(tree.open(&[height]).is_err());
            assert!(tree.open(&vec![0; MAX_REFERENCE_ROWS + 1]).is_err());
            let empty = tree.open(&[]).unwrap();
            assert!(empty.0.is_empty());
            assert!(empty.1 .0.is_empty());
            assert!(empty.1 .1.sibling_hashes.is_empty());
            assert_eq!(calls.lock().unwrap().len(), height.div_ceil(MAX_REFERENCE_ROWS));
            let original_rows = tree.row.clone();
            for fault in 0..4 {
                let original_rows = original_rows.clone();
                tree.row = Arc::new(move |indices| {
                    let mut rows = original_rows(indices)?;
                    match fault {
                        0 => {
                            rows.pop();
                        }
                        1 => rows.push(rows[0].clone()),
                        2 => {
                            rows[0].pop();
                        }
                        _ => rows[0][0] = Goldilocks::new(999),
                    }
                    Ok(rows)
                });
                assert!(tree.open(&indices).is_err());
            }
        }
    }

    #[test]
    fn replay_tree_uses_live_rng_cursor_and_rejects_bad_shapes() {
        let mmcs = mmcs([9; 32]);
        let row: Rows = Arc::new(|indices| {
            Ok(indices
                .iter()
                .map(|&i| vec![Goldilocks::new(i as u64), Goldilocks::new(7)])
                .collect())
        });
        let make = || vec![0; 16 * 4];
        assert!(Tree::commit(&mmcs, 64, 2, 16, 16, |_| Ok(make()), row.clone()).is_ok());
        let second = Tree::commit(&mmcs, 64, 2, 16, 16, |_| Ok(make()), row.clone()).unwrap().0;
        let fresh =
            Tree::commit(&super::super::mmcs([9; 32]), 64, 2, 16, 16, |_| Ok(make()), row.clone())
                .unwrap()
                .0;
        assert_ne!(second, fresh, "second commitment must continue the live salt stream");
        assert!(Tree::commit(&mmcs, 63, 2, 16, 16, |_| Ok(make()), row).is_err());
    }

    #[test]
    fn replay_tree_respects_mmcs_clone_fork() {
        let original = mmcs([5; 32]);
        let fork = original.clone();
        let row: Rows = Arc::new(|indices| {
            Ok(indices.iter().map(|_| vec![Goldilocks::new(11), Goldilocks::new(13)]).collect())
        });
        let cells = || {
            let mut result = vec![0; 16 * 4];
            for j in 0..16 {
                result[j] = 11;
                result[16 + j] = 13;
            }
            result
        };
        let a = Tree::commit(&original, 64, 2, 16, 16, |_| Ok(cells()), row.clone()).unwrap().0;
        let b = Tree::commit(&fork, 64, 2, 16, 16, |_| Ok(cells()), row).unwrap().0;
        assert_ne!(a, b, "an MMCS clone must fork its private salt stream");
    }
}

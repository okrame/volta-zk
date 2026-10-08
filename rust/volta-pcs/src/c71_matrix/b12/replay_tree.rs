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
use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use rand_010::RngExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use crate::c71_matrix::progress::Span;
use serde_json::json;

const LEAF: &[u8] = b"volta-zk/c71/b12/merkle/leaf/v1\0";
const SALTS: usize = 4;
const MAX_REFERENCE_HEIGHT: usize = 1 << 18;
pub(super) const MAX_REFERENCE_ROWS: usize = 1024;
pub(super) const CANONICAL_QUERY_ROWS: usize = 1 << 20;

pub(super) fn query_batch_rows(height: usize) -> usize {
    if height > MAX_REFERENCE_HEIGHT {
        CANONICAL_QUERY_ROWS
    } else {
        MAX_REFERENCE_ROWS
    }
}

/// Preserve the initial source-scan count while bounding the Merkle frontier.
/// Reduced cases use the same four-coset initial path, with tiny allocations.
pub(super) fn coset_group_size(height: usize, columns: usize) -> usize {
    if height <= MAX_REFERENCE_HEIGHT {
        if columns % 3 != 0 && (256..=1 << 16).contains(&height) {
            4
        } else {
            1
        }
    } else if columns == 128 {
        4
    } else if height >= 1 << 27 {
        2
    } else {
        1
    }
}

/// Selected W/A schedule. Heights distinguish S1, S2 and successors; all
/// extension stages have four native Fp3 columns, hence twelve base limbs.
pub(super) fn geometry(height: usize, columns: usize) -> Result<(usize, usize), String> {
    if height < 16 || !height.is_power_of_two() || columns == 0 {
        return Err("initial replay geometry differs".into());
    }
    if height <= MAX_REFERENCE_HEIGHT {
        let rows = 256.min(height) / coset_group_size(height, columns);
        return Ok((rows, (height / rows).max(16)));
    }
    let log_rows = match (height.ilog2(), columns) {
        (31 | 32, 128) => 20, // four cosets per scan: W/A still 1024/512 scans
        (29 | 30, 12) => 23,  // two cosets per scan, before retaining A
        (27 | 28, 12) => 21,  // paired S2 cosets while full S1 capacity is live
        (19..=26, 12) => 23,  // S3+: the excluded 2^24 never returns
        _ => return Err("large replay requires the selected W/A stage geometry".into()),
    };
    Ok((height.min(1 << log_rows), 1 << 12))
}

type Digest = [u8; 32];
pub(super) type Commitment = MerkleCap<Goldilocks, Digest>;
pub(super) type MultiProof = <HidingMmcs as Mmcs<Goldilocks>>::MultiProof;
pub(super) type Opening = (Vec<Vec<Vec<Goldilocks>>>, MultiProof);
pub(super) type Rows =
    Arc<dyn Fn(&[usize]) -> Result<DenseMatrix<Goldilocks>, String> + Send + Sync>;

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
        mut coset: impl FnMut(usize) -> Result<Vec<u64>, String>,
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
        if height > MAX_REFERENCE_HEIGHT && geometry(height, base_columns)? != (coset_rows, cut) {
            return Err("canonical replay stage schedule differs".into());
        }
        let cosets = height / coset_rows;
        if !cosets.is_power_of_two() || !cut.is_power_of_two() || cut < cosets || cut > height {
            return Err("replay coset count differs".into());
        }
        let physical_columns = base_columns.max(4);
        let mut phase = Span::start("pcs_commitment", json!({"height": height,
            "base_columns": base_columns, "coset_rows": coset_rows, "cosets": cosets, "cut": cut}))?;
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
            phase.checkpoint(|| json!({"completed_cosets": c + 1, "total_cosets": cosets,
                "leaf_hashes": work.leaf_hashes, "node_hashes": work.node_hashes,
                "salt_candidate_bytes": work.salt_candidate_bytes, "coset_cells": work.coset_cells}))?;
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
        phase.finish(json!({"completed_cosets": cosets, "leaf_hashes": work.leaf_hashes,
            "node_hashes": work.node_hashes, "salt_candidate_bytes": work.salt_candidate_bytes,
            "coset_cells": work.coset_cells, "retained_digest_bytes": memory.retained_digest_bytes,
            "retained_salt_offset_bytes": memory.salt_offset_bytes}))?;
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
        // Fix the native pruned-proof order first. Keep only requested paths,
        // never all regenerated subtrees (up to batch_count * 96 * cut bytes).
        let cut_log = self.cut.ilog2() as usize;
        let mut frontier = indices.to_vec();
        frontier.sort_unstable();
        frontier.dedup();
        let mut siblings = Vec::new();
        let mut paths = BTreeMap::<usize, Vec<(usize, usize, usize)>>::new();
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
                for missing in [(!has_left).then_some(left), (!has_right).then_some(right)]
                    .into_iter()
                    .flatten()
                {
                    if level < cut_log {
                        let leaf = missing << level;
                        paths.entry(leaf / self.cut).or_default().push((
                            level,
                            (leaf % self.cut) >> level,
                            siblings.len(),
                        ));
                        siblings.push([0; 32]);
                    } else {
                        siblings.push(self.top[level - cut_log][missing]);
                    }
                }
                parents.push(parent);
                i += usize::from(has_left) + usize::from(has_right);
            }
            frontier = parents;
        }
        let mut cursor = 0;
        let mut phase = Span::start("pcs_opening", json!({"height": self.height,
            "query_rows": indices.len(), "unique_subtrees": needed.len(), "batch_cap": batch_cap}))?;
        let mut batches = 0;
        let mut opened = vec![Vec::new(); indices.len()];
        let mut salts = vec![Vec::new(); indices.len()];
        for batch in needed.chunks(batch_cap / self.cut) {
            let batch_indices: Vec<_> = batch
                .iter()
                .flat_map(|&subtree| subtree * self.cut..(subtree + 1) * self.cut)
                .collect();
            let rows = (self.row)(&batch_indices)?;
            if rows.values.len() != batch_indices.len() * self.base_columns
                || rows.width != self.base_columns
            {
                return Err("replay opening row shape differs".into());
            }
            for (&subtree, values) in
                batch.iter().zip(rows.values.chunks_exact(self.cut * self.base_columns))
            {
                let regenerated = self.regenerate(subtree, values)?;
                let start = subtree * self.cut;
                while cursor < queries.len() && queries[cursor].0 < start + self.cut {
                    let (index, position) = queries[cursor];
                    opened[position] = vec![values[(index - start) * self.base_columns
                        ..(index - start + 1) * self.base_columns]
                        .to_vec()];
                    salts[position] = vec![regenerated.salts[index - start].to_vec()];
                    cursor += 1;
                }
                if let Some(requested) = paths.remove(&subtree) {
                    for (level, local, position) in requested {
                        siblings[position] = regenerated.levels[level][local];
                    }
                }
                // `regenerated` is dropped before the next subtree allocation.
            }
            batches += 1;
            phase.checkpoint(|| json!({"completed_queries": cursor, "completed_batches": batches}))?;
        }
        if !paths.is_empty() || cursor != queries.len() {
            return Err("replay pruned path coverage differs".into());
        }
        phase.finish(json!({"completed_queries": cursor, "completed_batches": batches,
            "regenerated_leaves": needed.len() * self.cut}))?;
        Ok((opened, (salts, PrunedMerklePaths { sibling_hashes: siblings })))
    }

    fn regenerate(&self, subtree: usize, rows: &[Goldilocks]) -> Result<Subtree, String> {
        let mut rng = stream_at(&self.private_stream, self.subtree_offsets[subtree])?;
        let mut salts = Vec::with_capacity(self.cut);
        let mut leaves = Vec::with_capacity(self.cut);
        if rows.len() != self.cut * self.base_columns {
            return Err("replay subtree row count differs".into());
        }
        for values in rows.chunks_exact(self.base_columns) {
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

    pub(super) fn geometry(&self) -> (usize, usize, usize, usize) {
        (self.height, self.cosets, self.coset_rows, self.cut)
    }
}

struct Subtree {
    salts: Vec<[Goldilocks; SALTS]>,
    levels: Vec<Vec<Digest>>,
}

fn clone_stream(rng: &PrivateRng) -> PrivateRng {
    rng.snapshot_at(rng.position()).expect("live committed private stream")
}

fn stream_at(original: &PrivateRng, offset: u64) -> Result<PrivateRng, String> {
    let mut rng = original.snapshot_at(offset)?;
    rng.buffer = Some(Box::new([0; 4096])); // sequential subtree reconstruction
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
            let (rows, cut) = geometry(height, 128).unwrap();
            allocation_geometry(height, 128);
            assert_eq!(rows, 1 << 20);
            assert_eq!(height / rows / coset_group_size(height, 128), passes);
            assert_eq!(cut, 4096);
            assert_eq!(rows * coset_group_size(height, 128) * 128 * 8, 4 << 30);
            assert_eq!(query_batch_rows(height), 1 << 20);
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
        assert!(geometry(1 << 31, 12).is_err());
        assert!(geometry(1 << 33, 128).is_err());
        assert!(geometry(1 << 31, 384).is_err());
    }

    fn allocation_geometry(height: usize, columns: usize) {
        let (rows, cut) = geometry(height, columns).unwrap();
        let group = coset_group_size(height, columns);
        let queries = query_batch_rows(height);
        println!(
            "C71_PCS_ALLOCATION_GEOMETRY {}",
            serde_json::json!({
                "height":height, "columns":columns, "coset_rows":rows, "group":group,
                "source_scans":height / rows / group,
                "pending_and_current_coset_capacity_bytes":group * rows * columns.max(4) * 8,
                "frontier_capacity_bytes":rows * (height / rows).ilog2() as usize * 32,
                "salt_cursors_capacity_bytes":rows * 8,
                "fft_column_and_twiddle_upper_bytes":3 * rows * 8,
                "retained_root_and_salt_offset_bytes":(2 * height / cut - 1) * 32 + height / cut * 8,
                "query_batch_rows":queries,
                "query_matrix_capacity_bytes":queries * columns * 8,
                "query_factor_capacity_bytes":32 * queries * (queries.ilog2() as usize + 1),
                "geometry_only":true, "credit":false
            })
        );
    }

    #[test]
    fn c71_b12_canonical_extension_geometry_tracks_every_native_stage_without_allocation() {
        for dimension in [34, 35] {
            let config = super::super::config(dimension).unwrap();
            let mut remaining = dimension - config.round_folding_factor(0);
            for round in 0..config.n_rounds() {
                let fold = config.round_folding_factor(round + 1);
                let height = config.inv_rate(round) * (1usize << (remaining - fold));
                let columns = 3 << fold;
                let (rows, cut) = geometry(height, columns).unwrap();
                allocation_geometry(height, columns);
                println!(
                    "C71_PCS_CHAIN_STAGE {}",
                    serde_json::json!({
                        "dimension":dimension, "round":round, "height":height,
                        "retained_capacity_at_commit_bytes": if dimension == 34 && round > 0 {
                            24usize << (remaining + config.round_folding_factor(round))
                        } else { 0 },
                        "geometry_only":true, "credit":false
                    })
                );
                if height > MAX_REFERENCE_HEIGHT {
                    let cap = match round {
                        0 => 1 << 23,
                        1 => 1 << 21,
                        _ => 1 << 23,
                    };
                    assert_eq!(rows, height.min(cap));
                    assert_eq!(cut, 4096);
                    assert_eq!(columns, 12);
                    assert_eq!(query_batch_rows(height), 1 << 20);
                    // Reject a different physical schedule before invoking any
                    // producer, allocating the domain or sampling private salts.
                    let rejected = if round >= 2 { 1 << 24 } else { rows / 2 };
                    assert!(Tree::commit(
                        &mmcs([1; 32]),
                        height,
                        columns,
                        rejected,
                        cut,
                        |_| panic!("invalid stage read source"),
                        Arc::new(|_| panic!("invalid stage read rows")),
                    )
                    .is_err());
                }
                remaining -= fold;
            }
        }
        for (height, columns) in [(1 << 30, 128), (1 << 31, 12), (1 << 29, 384)] {
            assert!(geometry(height, columns).is_err());
        }
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
                Ok(DenseMatrix::new(
                    indices
                        .iter()
                        .flat_map(|&r| row_values[r * columns..(r + 1) * columns].iter().copied())
                        .collect(),
                    columns,
                ))
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
                            rows.values.truncate(rows.values.len() - rows.width);
                        }
                        1 => rows.values.extend_from_within(..rows.width),
                        2 => {
                            rows.width -= 1;
                        }
                        _ => rows.values[0] = Goldilocks::new(999),
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
            Ok(DenseMatrix::new(
                indices
                    .iter()
                    .flat_map(|&i| [Goldilocks::new(i as u64), Goldilocks::new(7)])
                    .collect(),
                2,
            ))
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
            Ok(DenseMatrix::new(
                indices.iter().flat_map(|_| [Goldilocks::new(11), Goldilocks::new(13)]).collect(),
                2,
            ))
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

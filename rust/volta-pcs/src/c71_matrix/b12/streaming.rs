//! CPU refinement of consumed-coset hashing; no CUDA/service-rate credit.
use super::*;
use rand_010::RngExt;

const LEAF: &[u8] = b"volta-zk/c71/b12/merkle/leaf/v1\0";
const NODE: &[u8] = b"volta-zk/c71/b12/merkle/node/v1\0";

#[derive(Debug, Default)]
pub(super) struct HashWork {
    pub(super) field_reads: usize,
    pub(super) digest_word_writes: usize,
    pub(super) salt_candidate_bytes: u64,
    pub(super) hash_input_bytes: usize,
    pub(super) blake3_compressions: usize,
}

fn compressions(bytes: usize) -> usize {
    bytes.div_ceil(64) + bytes.div_ceil(1024) - 1
}

/// Each row is read completely before its first four column cells are reused
/// as raw digest words. Digests MUST NOT subsequently be reduced as field values.
/// `offsets` belongs to the retained upper-tree cache, not a new hash buffer.
fn leaves_in_place(
    cells: &mut [u64],
    rows: usize,
    columns: usize,
    subtree: usize,
    salts: &mut PrivateRng,
    offsets: &mut [u64],
) -> Result<HashWork, String> {
    let first = salts.position();
    if !subtree.is_power_of_two() || offsets.len() != rows.div_ceil(subtree) {
        return Err("salt offset shape differs".into());
    }
    let mut work = hash_rows_in_place(cells, rows, columns, |row| {
        if row % subtree == 0 {
            offsets[row / subtree] = salts.position();
        }
        std::array::from_fn(|_| salts.random())
    })?;
    work.salt_candidate_bytes = salts.position() - first;
    Ok(work)
}

pub(super) fn hash_rows_in_place(
    cells: &mut [u64],
    rows: usize,
    columns: usize,
    mut salts: impl FnMut(usize) -> [Goldilocks; 4],
) -> Result<HashWork, String> {
    if rows == 0 || columns == 0 || rows.checked_mul(columns.max(4)) != Some(cells.len()) {
        return Err("consumed coset shape differs".into());
    }
    let mut work = HashWork::default();
    for row in 0..rows {
        let mut hash = blake3::Hasher::new();
        hash.update(LEAF);
        for col in 0..columns {
            let x = cells[col * rows + row];
            if x >= Goldilocks::ORDER_U64 {
                return Err("noncanonical coset field word".into());
            }
            hash.update(&x.to_le_bytes());
        }
        for salt in salts(row) {
            hash.update(&salt.as_canonical_u64().to_le_bytes());
        }
        let digest = hash.finalize();
        for (col, word) in digest.as_bytes().chunks_exact(8).enumerate() {
            cells[col * rows + row] = u64::from_le_bytes(word.try_into().unwrap());
        }
    }
    let length = LEAF.len() + 8 * (columns + 4);
    work.field_reads = rows * columns;
    work.digest_word_writes = 4 * rows;
    work.hash_input_bytes = rows * length;
    work.blake3_compressions = rows * compressions(length);
    Ok(work)
}

/// Natural-order sampler scan. Start/current slots already belong to the coset
/// workspace. The callback records immutable upper-cache subtree offsets.
pub(super) fn prepare_offsets(
    rng: &mut PrivateRng,
    cosets: usize,
    starts: &mut [u64],
    mut record: impl FnMut(usize, u64),
) -> Result<u64, String> {
    if !cosets.is_power_of_two() || starts.is_empty() {
        return Err("salt prescan shape".into());
    }
    let rows = cosets.checked_mul(starts.len()).ok_or("salt prescan overflow")?;
    let first = rng.position();
    for row in 0..rows {
        if row % cosets == 0 {
            starts[row / cosets] = rng.position();
        }
        record(row, rng.position());
        for _ in 0..4 {
            let _: Goldilocks = rng.random();
        }
    }
    Ok(rng.position() - first)
}

pub(super) fn strided_leaves_in_place(
    cells: &mut [u64],
    rows: usize,
    columns: usize,
    original_stream: &PrivateRng,
    current: &mut [u64],
) -> Result<HashWork, String> {
    if current.len() != rows || current.iter().any(|&p| p > (1 << 40) - 32) {
        return Err("strided salt offsets differ".into());
    }
    let mut candidates = 0;
    let mut work = hash_rows_in_place(cells, rows, columns, |row| {
        // Same private stream/root only. Clone the XOF state, never fork coins
        // or rehash the seed for every leaf. No heap allocation is needed.
        let mut salt = PrivateRng {
            reader: original_stream.reader.clone(),
            remaining: (1 << 40) - current[row],
        };
        salt.reader.set_position(current[row]);
        let result = std::array::from_fn(|_| salt.random());
        candidates += salt.position() - current[row];
        current[row] = salt.position();
        result
    })?;
    work.salt_candidate_bytes = candidates;
    Ok(work)
}

pub(super) fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(NODE);
    hash.update(&left);
    hash.update(&right);
    hash.finalize().into()
}

pub(super) fn write_digest(cells: &mut [u64], stride: usize, row: usize, value: [u8; 32]) {
    for (col, word) in value.chunks_exact(8).enumerate() {
        cells[col * stride + row] = u64::from_le_bytes(word.try_into().unwrap());
    }
}

/// Coset c holds natural leaves c+Q*j. Each j owns log2(Q) frontier
/// entries. On the final coset their roots replace the consumed leaf cells.
pub(super) fn merge_coset(
    cells: &mut [u64],
    rows: usize,
    coset: usize,
    cosets: usize,
    frontier: &mut [[u8; 32]],
) -> Result<usize, String> {
    if !cosets.is_power_of_two()
        || coset >= cosets
        || rows == 0
        || cells.len() < 4 * rows
        || frontier.len() != rows * (cosets.ilog2() as usize)
    {
        return Err("strided Merkle frontier shape".into());
    }
    let levels = cosets.ilog2() as usize;
    let mut nodes = 0;
    for row in 0..rows {
        let mut value = digest(cells, rows, row);
        let mut level = 0;
        while (coset >> level) & 1 == 1 {
            value = node_hash(frontier[row * levels + level], value);
            level += 1;
            nodes += 1;
        }
        if level == levels {
            write_digest(cells, rows, row, value);
        } else {
            frontier[row * levels + level] = value;
        }
    }
    Ok(nodes)
}

pub(super) fn digest(cells: &[u64], stride: usize, row: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    for col in 0..4 {
        bytes[8 * col..8 * col + 8].copy_from_slice(&cells[col * stride + row].to_le_bytes());
    }
    bytes
}

/// Reference subtree reduction after leaf consumption. Upper nodes are copied
/// to the existing cache by the caller before reducing another level.
pub(super) fn reduce_in_place(cells: &mut [u64], stride: usize, live: usize) -> Result<HashWork, String> {
    if !live.is_power_of_two() || live < 2 || live > stride || cells.len() < 4 * stride {
        return Err("digest reduction shape differs".into());
    }
    for row in 0..live / 2 {
        let left = digest(cells, stride, 2 * row);
        let right = digest(cells, stride, 2 * row + 1);
        let mut hash = blake3::Hasher::new();
        hash.update(NODE);
        hash.update(&left);
        hash.update(&right);
        for (col, word) in hash.finalize().as_bytes().chunks_exact(8).enumerate() {
            cells[col * stride + row] = u64::from_le_bytes(word.try_into().unwrap());
        }
    }
    Ok(HashWork {
        field_reads: 4 * live,
        digest_word_writes: 2 * live,
        hash_input_bytes: (live / 2) * (NODE.len() + 64),
        blake3_compressions: (live / 2) * compressions(NODE.len() + 64),
        ..HashWork::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_commit::Mmcs;
    use p3_matrix::dense::RowMajorMatrix;

    #[test]
    fn c71_b12_streaming_hash_matches_native_salts_roots_and_seek() {
        // 128 columns crosses BLAKE3's chunk boundary; non-square/ragged batches
        // and stream reuse exercise the actual salt order for consecutive roots.
        let seed = [37; 32];
        let native = mmcs(seed);
        let mut rng = PrivateRng::from_seed(seed);
        for columns in [4, 7, 128, 384] {
            let rows = 16;
            let values: Vec<_> =
                (0..rows * columns).map(|i| Goldilocks::new((i as u64) * 7919)).collect();
            let (root, data) = native.commit_matrix(RowMajorMatrix::new(values.clone(), columns));
            let mut cells: Vec<_> = (0..columns)
                .flat_map(|c| {
                    let values = &values;
                    (0..rows).map(move |r| values[r * columns + c].as_canonical_u64())
                })
                .collect();
            let mut offsets = [0; 4];
            let work =
                leaves_in_place(&mut cells, rows, columns, 4, &mut rng, &mut offsets).unwrap();
            assert_eq!(work.field_reads, rows * columns);
            assert!(work.salt_candidate_bytes >= 32 * rows as u64);
            for block in (0..4).rev() {
                let mut replay = PrivateRng::replay_at(seed, offsets[block]).unwrap();
                for row in block * 4..block * 4 + 4 {
                    let (_, proof) = native.open_multi_batch(&[row], &data);
                    let salt: Vec<Goldilocks> = (0..4).map(|_| replay.random()).collect();
                    assert_eq!(salt, proof.0[0][0]);
                    let expected = SerializingHasher::new(DomainHash(LEAF)).hash_iter(
                        values[row * columns..(row + 1) * columns].iter().copied().chain(salt),
                    );
                    assert_eq!(digest(&cells, rows, row), expected);
                }
            }
            for level in (1..=rows.ilog2()).rev() {
                reduce_in_place(&mut cells, rows, 1 << level).unwrap();
            }
            assert_eq!(digest(&cells, rows, 0), root.roots()[0]);
            eprintln!("stream_hash columns={columns} rows={rows} work={work:?} hasher_state={} rng_state={}",
                std::mem::size_of::<blake3::Hasher>(),std::mem::size_of::<PrivateRng>());
        }
        assert!(PrivateRng::replay_at(seed, 1 << 40).is_err());
        assert!(PrivateRng::replay_at(seed, (1 << 40) + 1).is_err());
        let original_stream = PrivateRng::from_seed(seed);
        assert!(
            strided_leaves_in_place(&mut [0; 4], 1, 4, &original_stream, &mut [1 << 40]).is_err()
        );
        assert!(
            leaves_in_place(&mut [Goldilocks::ORDER_U64; 4], 1, 4, 1, &mut rng, &mut [0]).is_err()
        );
    }

    #[test]
    fn c71_b12_streaming_strided_cosets_match_native_root() {
        let (rows, cosets, columns) = (16, 8, 128);
        let height = rows * cosets;
        let seed = [23; 32];
        let values: Vec<_> =
            (0..height * columns).map(|i| Goldilocks::new((i as u64) * 8191)).collect();
        let native = mmcs(seed);
        let (root, data) = native.commit_matrix(RowMajorMatrix::new(values.clone(), columns));
        let stream = PrivateRng::from_seed(seed);
        let mut scan = PrivateRng::from_seed(seed);
        let mut starts = vec![0; rows];
        let mut upper_offsets = vec![0; height / 16];
        let prescan = prepare_offsets(&mut scan, cosets, &mut starts, |row, offset| {
            if row % 16 == 0 {
                upper_offsets[row / 16] = offset;
            }
        })
        .unwrap();
        let mut current = starts.clone();
        let mut frontier = vec![[0; 32]; rows * cosets.ilog2() as usize];
        let mut cells = vec![0; rows * columns];
        let (mut replay_bytes, mut nodes) = (0, 0);
        for c in 0..cosets {
            for col in 0..columns {
                for j in 0..rows {
                    cells[col * rows + j] =
                        values[(c + cosets * j) * columns + col].as_canonical_u64();
                }
            }
            let work =
                strided_leaves_in_place(&mut cells, rows, columns, &stream, &mut current).unwrap();
            replay_bytes += work.salt_candidate_bytes;
            for j in 0..rows {
                let global = c + cosets * j;
                let (_, proof) = native.open_multi_batch(&[global], &data);
                let leaf = SerializingHasher::new(DomainHash(LEAF)).hash_iter(
                    values[global * columns..(global + 1) * columns]
                        .iter()
                        .copied()
                        .chain(proof.0[0][0].iter().copied()),
                );
                assert_eq!(digest(&cells, rows, j), leaf);
            }
            nodes += merge_coset(&mut cells, rows, c, cosets, &mut frontier).unwrap();
        }
        assert_eq!(replay_bytes, prescan);
        assert_eq!(&current[..rows - 1], &starts[1..]);
        assert_eq!(current[rows - 1], scan.position());
        for level in (1..=rows.ilog2()).rev() {
            nodes += (1 << level) / 2;
            reduce_in_place(&mut cells, rows, 1 << level).unwrap();
        }
        assert_eq!(nodes, height - 1);
        assert_eq!(digest(&cells, rows, 0), root.roots()[0]);
        for (block, &offset) in upper_offsets.iter().enumerate() {
            let mut replay = PrivateRng::replay_at(seed, offset).unwrap();
            let salts: Vec<Goldilocks> = (0..4).map(|_| replay.random()).collect();
            assert_eq!(salts, native.open_multi_batch(&[block * 16], &data).1 .0[0][0]);
        }
        eprintln!("strided_hash height={height} cosets={cosets} prescan_bytes={prescan} replay_bytes={replay_bytes} frontier_bytes={} offsets_bytes={}",frontier.len()*32,starts.len()*16);
    }

    #[test]
    fn c71_b12_streaming_sampler_rejection_consumes_variable_offsets() {
        // Force the otherwise rare rejection through the actual field sampler.
        struct Tape {
            words: std::vec::IntoIter<u64>,
            bytes: usize,
        }
        impl rand_010::TryRng for Tape {
            type Error = std::convert::Infallible;
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                self.bytes += 8;
                Ok(self.words.next().unwrap())
            }
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                unreachable!()
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
                unreachable!()
            }
        }
        let mut rng = Tape {
            words: vec![u64::MAX, Goldilocks::ORDER_U64, 9, 10, 11, 12].into_iter(),
            bytes: 0,
        };
        let salts: [Goldilocks; 4] = std::array::from_fn(|_| rng.random());
        assert_eq!(salts.map(|x| x.as_canonical_u64()), [9, 10, 11, 12]);
        assert_eq!(rng.bytes, 48); // a 32*row seek would corrupt every later root
    }
}

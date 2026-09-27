//! Public i16-input lookup, with X/Y and the fixed histogram in the SAME source.
//! Reuses range's fraction GKR; it does not commit inverses or a trace.

use super::*;

component_wire!(Proof { roots, layers, leaves, products });

pub(super) struct Table<'a> {
    pub profile: u8,
    pub lower: i16,
    // Consecutive signed inputs. MIN is an overflow marker, never an output.
    pub outputs: Outputs<'a>,
}

#[derive(Clone, Copy)]
pub(super) enum Outputs<'a> {
    I16(&'a [i16]),
    I32(&'a [i32]),
}

impl Outputs<'_> {
    pub fn len(self) -> usize {
        match self {
            Self::I16(v) => v.len(),
            Self::I32(v) => v.len(),
        }
    }

    fn get(self, i: usize) -> i32 {
        match self {
            Self::I16(v) => i32::from(v[i]),
            Self::I32(v) => v[i],
        }
    }

    fn overflow(self) -> i32 {
        match self {
            Self::I16(_) => i32::from(i16::MIN),
            Self::I32(_) => i32::MIN,
        }
    }

    fn encode(self, bytes: &mut Vec<u8>) {
        match self {
            Self::I16(v) => v.iter().for_each(|y| bytes.extend(y.to_le_bytes())),
            Self::I32(v) => v.iter().for_each(|y| bytes.extend(y.to_le_bytes())),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Block {
    Query { profile: u8, len: usize },
    Table { index: usize, first: usize, len: usize },
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Row {
    Query(u8),
    Table(usize),
}

pub(super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub blocks: &'a [Block],
    pub tables: &'a [Table<'a>],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct SourceWork {
    pub descriptor_capacity_bytes: usize,
    pub binding_frame_capacity_bytes: usize,
    pub binding_frame_capacity_while_attempt_live_bytes: usize,
    pub query_cache_capacity_bytes: usize,
    pub histogram_cache_capacity_bytes: usize,
    pub upper_tree_capacity_bytes: usize,
    pub eq_scratch_capacity_bytes: usize,
    /// Named descriptor/cache/tree/Eq subset only; excludes proof, correlation rows,
    /// transcript internals, allocator metadata and caller storage.
    pub named_heap_peak_bytes: usize,
    pub named_heap_peak_is_complete: bool,
    pub rows_backing_capacity_bytes: usize,
    pub proof_heap_capacity_bytes: usize,
    pub proof_logical_heap_bytes: usize,
    pub triples_capacity_bytes: usize,
    pub triples_logical_bytes: usize,
    pub point_capacity_bytes: usize,
    pub point_logical_bytes: usize,
    pub dimensions_transient_capacity_bytes: usize,
    pub attempt_encode_capacity_bytes: usize,
    pub binding_frame_logical_bytes: usize,
    pub binding_table_output_encoded_bytes: usize,
    pub declared_subtree_stack_bytes: usize,
    pub declared_nested_stack_payload_lower_bound_bytes: usize,
    pub declared_stack_is_complete: bool,
    pub owned_heap_peak_bytes: usize,
    pub owned_capacity_is_complete: bool,
    /// Excludes caller correlation backing, Statement/public tables and blocks,
    /// getter/provider state, Fs state, allocator metadata, transient
    /// old+new allocations during Vec growth, and compiler stack.
    pub owned_heap_peak_excludes_external: bool,
    pub auth_size_bytes: usize,
    pub triple_size_bytes: usize,
    pub layer_size_bytes: usize,
    pub compact_block_size_bytes: usize,
    pub attempt_context_size_bytes: usize,
    pub descriptor_size_bytes: usize,
    pub query_cache_size_bytes: usize,
    pub proof_size_bytes: usize,
    pub pending_auth_size_bytes: usize,
    pub bind_work_size_bytes: usize,
    pub dimension_work_size_bytes: usize,
    pub source_work_size_bytes: usize,
    pub correlation_rows_reserved: u64,
    pub correlation_rows_consumed: u64,
    pub denominator_inversions: u64,
    pub denominator_zero_comparisons: u64,
    pub correlation_row_copy_bytes: u64,
    pub cache_payload_write_bytes: u64,
    pub cache_payload_read_bytes: u64,
    pub binding_frame_payload_write_bytes: u64,
    pub cache_query_decodes: u64,
    pub cache_histogram_reads: u64,
    pub public_table_output_reads: u64,
    pub descriptor_row_calls: u64,
    pub dimension_validation_passes: u64,
    pub dimension_table_metadata_visits: u64,
    pub dimension_block_visits: u64,
    pub dimension_coverage_interval_visits: u64,
    pub query_getter_calls: u64,
    pub histogram_getter_calls: u64,
    pub public_tag_scans: u64,
    pub leaf_builds: u64,
    pub tree_reductions: u64,
    pub replay_leaf_reads: u64,
    pub replay_reductions: u64,
    pub endpoint_leaf_reads: u64,
    pub equality_multiplications: u64,
    pub equality_subtractions: u64,
    pub tree: range::SourceTreeWork,
}

#[derive(Clone, Copy)]
enum CompactKind {
    Query { profile: u8, first: usize },
    Table { first: usize },
}

#[derive(Clone, Copy)]
struct CompactBlock {
    begin: usize,
    end: usize,
    kind: CompactKind,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
struct BindWork {
    frame_capacity_bytes: usize,
    frame_logical_bytes: usize,
    attempt_encode_capacity_bytes: usize,
    frame_capacity_while_attempt_live_bytes: usize,
    table_output_encoded_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
struct DimensionWork {
    coverage_outer_capacity_bytes: usize,
    coverage_inner_capacity_bytes: usize,
    offsets_capacity_bytes: usize,
}

struct Descriptor {
    blocks: Vec<CompactBlock>,
    table_offsets: Vec<usize>,
    live: usize,
    queries: usize,
    rows: usize,
    bits: usize,
    dimensions_work: DimensionWork,
}

#[derive(Clone, Copy)]
enum CompactRow {
    Query { profile: u8, query: usize },
    Table(usize),
    Padding,
}

impl Descriptor {
    fn new(s: &Statement<'_>) -> Result<Self, String> {
        let (rows, queries, offsets, dimensions_work) = s.dimensions()?;
        let mut blocks = Vec::with_capacity(s.blocks.len());
        let (mut begin, mut query_first) = (0usize, 0usize);
        for &block in s.blocks {
            let (len, kind) = match block {
                Block::Query { profile, len } => {
                    let kind = CompactKind::Query { profile, first: query_first };
                    query_first += len;
                    (len, kind)
                }
                Block::Table { index, first, len } => {
                    (len, CompactKind::Table { first: offsets[index] + first })
                }
            };
            blocks.push(CompactBlock { begin, end: begin + len, kind });
            begin += len;
        }
        let live = rows + queries;
        Ok(Self {
            blocks,
            table_offsets: offsets,
            live,
            queries,
            rows,
            bits: live.next_power_of_two().ilog2() as usize,
            dimensions_work,
        })
    }

    fn row(&self, index: usize) -> CompactRow {
        if index >= self.live {
            return CompactRow::Padding;
        }
        let at = self.blocks.partition_point(|block| block.end <= index);
        let block = self.blocks[at];
        let local = index - block.begin;
        match block.kind {
            CompactKind::Query { profile, first } => {
                CompactRow::Query { profile, query: first + local }
            }
            CompactKind::Table { first } => CompactRow::Table(first + local),
        }
    }

    fn capacity_bytes(&self) -> usize {
        self.blocks.capacity() * core::mem::size_of::<CompactBlock>()
            + self.table_offsets.capacity() * core::mem::size_of::<usize>()
    }
}

enum QueryCache {
    Narrow(Vec<[u8; 4]>),
    Wide(Vec<[u8; 6]>),
}

impl QueryCache {
    fn build(
        descriptor: &Descriptor,
        read: &impl Fn(usize) -> (i16, i32),
        wide: bool,
    ) -> Result<(Self, u64), String> {
        if wide {
            let mut cache = Vec::with_capacity(descriptor.queries);
            for i in 0..descriptor.live {
                if matches!(descriptor.row(i), CompactRow::Query { .. }) {
                    let (x, y) = read(i);
                    let mut row = [0u8; 6];
                    row[..2].copy_from_slice(&x.to_le_bytes());
                    row[2..].copy_from_slice(&y.to_le_bytes());
                    cache.push(row);
                }
            }
            Ok((Self::Wide(cache), descriptor.queries as u64))
        } else {
            let mut cache = Vec::with_capacity(descriptor.queries);
            for i in 0..descriptor.live {
                if matches!(descriptor.row(i), CompactRow::Query { .. }) {
                    let (x, y) = read(i);
                    let y = i16::try_from(y).map_err(|_| "narrow lookup query output differs")?;
                    let mut row = [0u8; 4];
                    row[..2].copy_from_slice(&x.to_le_bytes());
                    row[2..].copy_from_slice(&y.to_le_bytes());
                    cache.push(row);
                }
            }
            Ok((Self::Narrow(cache), descriptor.queries as u64))
        }
    }

    fn get(&self, index: usize) -> (i16, i32) {
        match self {
            Self::Narrow(rows) => {
                let row = rows[index];
                (
                    i16::from_le_bytes(row[..2].try_into().unwrap()),
                    i32::from(i16::from_le_bytes(row[2..].try_into().unwrap())),
                )
            }
            Self::Wide(rows) => {
                let row = rows[index];
                (
                    i16::from_le_bytes(row[..2].try_into().unwrap()),
                    i32::from_le_bytes(row[2..].try_into().unwrap()),
                )
            }
        }
    }

    fn capacity_bytes(&self) -> usize {
        match self {
            Self::Narrow(v) => v.capacity() * 4,
            Self::Wide(v) => v.capacity() * 6,
        }
    }
}

fn table_tag(s: &Statement<'_>, descriptor: &Descriptor, j: usize) -> Fp3 {
    let table = descriptor.table_offsets.partition_point(|&offset| offset <= j) - 1;
    let local = j - descriptor.table_offsets[table];
    let t = &s.tables[table];
    let y = t.outputs.get(local);
    tag(
        (i64::from(t.lower) + local as i64) as i16,
        y,
        t.profile + if y == t.outputs.overflow() { 60 } else { 0 },
    )
}

fn fraction_leaf(
    s: &Statement<'_>,
    descriptor: &Descriptor,
    queries: &QueryCache,
    histogram: &[i32],
    alpha: Fp3,
    index: usize,
) -> [Fp3; 2] {
    match descriptor.row(index) {
        CompactRow::Query { profile, query } => {
            let (x, y) = queries.get(query);
            [Fp3::ONE, alpha - tag(x, y, profile)]
        }
        CompactRow::Table(j) => {
            [-signed(i64::from(histogram[j])), alpha - table_tag(s, descriptor, j)]
        }
        CompactRow::Padding => [Fp3::ZERO, Fp3::ONE],
    }
}

fn combine([p, q]: [Fp3; 2], [r, s]: [Fp3; 2]) -> [Fp3; 2] {
    [p * s + r * q, q * s]
}

struct CutTree {
    levels: Vec<Vec<[Fp3; 2]>>,
    bits: usize,
    cut: usize,
}

impl CutTree {
    const CUT: usize = 4;

    fn build(mut leaf: impl FnMut(usize) -> [Fp3; 2], bits: usize, work: &mut SourceWork) -> Self {
        let cut_bits = bits.min(Self::CUT);
        let cut_nodes = 1usize << (bits - cut_bits);
        let mut cut = Vec::with_capacity(cut_nodes);
        for chunk in 0..cut_nodes {
            let mut nodes = [[Fp3::ZERO; 2]; 1 << Self::CUT];
            let mut len = 1 << cut_bits;
            for i in 0..len {
                work.leaf_builds += 1;
                nodes[i] = leaf((chunk << cut_bits) + i);
            }
            while len > 1 {
                for i in 0..len / 2 {
                    work.tree_reductions += 1;
                    nodes[i] = combine(nodes[2 * i], nodes[2 * i + 1]);
                }
                len /= 2;
            }
            cut.push(nodes[0]);
        }
        let mut levels = Vec::with_capacity(bits - cut_bits + 1);
        levels.push(cut);
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|x| {
                    work.tree_reductions += 1;
                    combine(x[0], x[1])
                })
                .collect();
            levels.push(next);
        }
        work.upper_tree_capacity_bytes = levels.capacity() * core::mem::size_of::<Vec<[Fp3; 2]>>()
            + levels.iter().map(|v| v.capacity() * core::mem::size_of::<[Fp3; 2]>()).sum::<usize>();
        Self { levels, bits, cut: cut_bits }
    }

    fn root(&self) -> [Fp3; 2] {
        self.levels.last().unwrap()[0]
    }

    fn node(
        &self,
        height: usize,
        position: usize,
        leaf: &impl Fn(usize) -> [Fp3; 2],
        work: &std::cell::Cell<(u64, u64)>,
    ) -> [Fp3; 2] {
        if height >= self.cut {
            return self.levels[height - self.cut][position];
        }
        let begin = position << height;
        let mut nodes = [[Fp3::ZERO; 2]; 1 << Self::CUT];
        let mut len = 1 << height;
        for i in 0..len {
            let (reads, reductions) = work.get();
            work.set((reads + 1, reductions));
            nodes[i] = leaf(begin + i);
        }
        while len > 1 {
            for i in 0..len / 2 {
                let (reads, reductions) = work.get();
                work.set((reads, reductions + 1));
                nodes[i] = combine(nodes[2 * i], nodes[2 * i + 1]);
            }
            len /= 2;
        }
        nodes[0]
    }

    fn children(
        &self,
        layer: usize,
        index: usize,
        leaf: &impl Fn(usize) -> [Fp3; 2],
        work: &std::cell::Cell<(u64, u64)>,
    ) -> [Fp3; 4] {
        let height = self.bits - layer - 1;
        let a = self.node(height, 2 * index, leaf, work);
        let b = self.node(height, 2 * index + 1, leaf, work);
        [a[0], a[1], b[0], b[1]]
    }
}

fn for_each_equality(point: &[Fp3], mut visit: impl FnMut(usize, Fp3)) -> (u64, u64, usize) {
    if point.is_empty() {
        visit(0, Fp3::ONE);
        return (0, 0, 0);
    }
    let q = point.len();
    let mut weights = Vec::with_capacity(q + 1);
    weights.resize(q + 1, Fp3::ONE);
    for bit in 0..q {
        weights[bit + 1] = weights[bit] * (Fp3::ONE - point[bit]);
    }
    let mut mul = q as u64;
    let mut sub = q as u64;
    visit(0, weights[q]);
    for prefix in 1..(1usize << q) {
        let start = q - 1 - prefix.trailing_zeros() as usize;
        for bit in start..q {
            let factor = if (prefix >> (q - 1 - bit)) & 1 == 0 {
                sub += 1;
                Fp3::ONE - point[bit]
            } else {
                point[bit]
            };
            weights[bit + 1] = weights[bit] * factor;
            mul += 1;
        }
        visit(prefix, weights[q]);
    }
    (mul, sub, weights.capacity() * core::mem::size_of::<Fp3>())
}

pub(super) struct Proof {
    roots: [Fp3; 2], // denominator and inverse; numerator is PUBLIC zero
    layers: Vec<range::Layer>,
    leaves: [Fp3; 5], // original X/Y/M corrections, then two affine tags
    products: [Fp3; 2],
}

pub(super) struct Pending<T> {
    pub point: Vec<Fp3>,   // combined query/table/dummy domain, MSB first
    pub originals: [T; 3], // weighted X, Y, histogram; no reauthentication
}

pub(super) fn required(bits: usize) -> usize {
    2 * bits * bits + 5 * bits + 6
}

fn tag(x: i16, y: i32, profile: u8) -> Fp3 {
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    signed(i64::from(x)) + omega * signed(i64::from(y)) + omega * omega * signed(i64::from(profile))
}

impl Statement<'_> {
    fn dimensions(&self) -> Result<(usize, usize, Vec<usize>, DimensionWork), String> {
        if self.blocks.is_empty()
            || self.blocks.len() > 65791
            || self.tables.is_empty()
            || self.tables.len() > 60
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 lookup fixed context or block count differs".into());
        }
        let mut seen = [false; 60];
        let mut rows = 0usize;
        for t in self.tables {
            if t.profile >= 60
                || seen[t.profile as usize]
                || t.outputs.len() == 0
                || t.outputs.len() > 65535
                || t.lower == i16::MIN
                || i64::from(t.lower) + t.outputs.len() as i64 - 1 > 32767
            {
                return Err("B12 lookup public table domain or profile differs".into());
            }
            seen[t.profile as usize] = true;
            rows += t.outputs.len();
        }
        let mut coverage = vec![Vec::new(); self.tables.len()];
        let mut queries = 0usize;
        let mut offsets = Vec::with_capacity(self.tables.len());
        let mut offset = 0;
        for t in self.tables {
            offsets.push(offset);
            offset += t.outputs.len();
        }
        // Validate compact blocks before allocating any expanded cell domain.
        for &block in self.blocks {
            match block {
                Block::Query { profile, len } => {
                    if profile >= 60 || !seen[profile as usize] || len == 0 || len > 1 << 28 {
                        return Err("B12 lookup query block differs".into());
                    }
                    queries += len;
                    if queries > 1 << 28 {
                        return Err("B12 lookup query count exceeds 2^28".into());
                    }
                }
                Block::Table { index, first, len } => {
                    let t = self.tables.get(index).ok_or("B12 lookup table block missing")?;
                    if len == 0 || first > t.outputs.len() || len > t.outputs.len() - first {
                        return Err("B12 lookup table interval differs".into());
                    }
                    coverage[index].push((first, len));
                }
            }
        }
        if queries == 0 {
            return Err("B12 lookup has no query cells".into());
        }
        for (t, intervals) in self.tables.iter().zip(&mut coverage) {
            intervals.sort_unstable();
            let mut end = 0;
            for &(first, len) in intervals.iter() {
                if first != end {
                    return Err("B12 lookup table coverage differs".into());
                }
                end += len;
            }
            if end != t.outputs.len() {
                return Err("B12 lookup table coverage is incomplete".into());
            }
        }
        let work = DimensionWork {
            coverage_outer_capacity_bytes: coverage.capacity()
                * core::mem::size_of::<Vec<(usize, usize)>>(),
            coverage_inner_capacity_bytes: coverage
                .iter()
                .map(|v| v.capacity() * core::mem::size_of::<(usize, usize)>())
                .sum(),
            offsets_capacity_bytes: offsets.capacity() * core::mem::size_of::<usize>(),
        };
        Ok((rows, queries, offsets, work))
    }

    #[cfg(test)]
    fn public(&self) -> Result<(Vec<Fp3>, Vec<Row>), String> {
        let (rows, queries, offsets, _) = self.dimensions()?;
        let tags = self
            .tables
            .iter()
            .flat_map(|t| {
                (0..t.outputs.len()).map(move |j| {
                    let y = t.outputs.get(j);
                    tag(
                        (i64::from(t.lower) + j as i64) as i16,
                        y,
                        t.profile + if y == t.outputs.overflow() { 60 } else { 0 },
                    )
                })
            })
            .collect();
        let mut domain = Vec::with_capacity(rows + queries);
        for &block in self.blocks {
            match block {
                Block::Query { profile, len } => {
                    domain.extend(std::iter::repeat_n(Row::Query(profile), len))
                }
                Block::Table { index, first, len } => {
                    domain.extend((first..first + len).map(|j| Row::Table(offsets[index] + j)))
                }
            }
        }
        Ok((tags, domain))
    }

    pub fn required(&self) -> Result<usize, String> {
        let (rows, queries, _, _) = self.dimensions()?;
        Ok(required((rows + queries).next_power_of_two().ilog2() as usize))
    }

    fn bind(&self, fs: &mut Fs) -> Result<(Descriptor, Fp3, BindWork), String> {
        let descriptor = Descriptor::new(self)?;
        let wide = self.tables.iter().any(|t| matches!(t.outputs, Outputs::I32(_)));
        let domain: &[u8] = if wide {
            b"C71-lookup-B12-v3;i16-input;typed-i16-i32-output;MIN-overflow;original-A"
        } else {
            b"C71-lookup-B12-v2;fixed-X-Y-M;public-blocks;overflow-profile-plus-60;original-A"
        };
        let attempt = self.attempt.encode();
        let attempt_encode_capacity_bytes = attempt.capacity();
        let block_bytes = self.blocks.iter().map(|b| match b {
            Block::Query { .. } => 10,
            Block::Table { .. } => 25,
        });
        let table_bytes = self.tables.iter().map(|t| {
            11 + usize::from(wide)
                + t.outputs.len()
                    * match t.outputs {
                        Outputs::I16(_) => 2,
                        Outputs::I32(_) => 4,
                    }
        });
        let frame_length = [domain.len(), 32, 8, self.profile.len(), 32, attempt.len(), 8, 8]
            .into_iter()
            .chain(block_bytes)
            .chain(table_bytes)
            .try_fold(0usize, usize::checked_add)
            .ok_or("B12 lookup binding length overflow")?;
        let mut bytes = Vec::with_capacity(frame_length);
        bytes.extend(domain);
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(&attempt);
        let binding_frame_capacity_while_attempt_live_bytes = bytes.capacity();
        drop(attempt);
        bytes.extend((self.blocks.len() as u64).to_le_bytes());
        for &block in self.blocks {
            match block {
                Block::Query { profile, len } => {
                    bytes.extend([0, profile]);
                    bytes.extend((len as u64).to_le_bytes());
                }
                Block::Table { index, first, len } => {
                    bytes.push(1);
                    for v in [index, first, len] {
                        bytes.extend((v as u64).to_le_bytes());
                    }
                }
            }
        }
        bytes.extend((self.tables.len() as u64).to_le_bytes());
        let mut binding_table_output_encoded_bytes = 0usize;
        for t in self.tables {
            bytes.push(t.profile);
            if wide {
                bytes.push(match t.outputs {
                    Outputs::I16(_) => 2,
                    Outputs::I32(_) => 4,
                });
            }
            bytes.extend(t.lower.to_le_bytes());
            bytes.extend((t.outputs.len() as u64).to_le_bytes());
            binding_table_output_encoded_bytes += t.outputs.len()
                * match t.outputs {
                    Outputs::I16(_) => 2,
                    Outputs::I32(_) => 4,
                };
            t.outputs.encode(&mut bytes);
        }
        debug_assert_eq!(bytes.len(), frame_length);
        let binding_frame_logical_bytes = bytes.len();
        let binding_frame_capacity_bytes = bytes.capacity();
        fs.set_phase(0xd00);
        fs.record(0xb0, &bytes);
        let alpha = fs.fp3();
        // Every honest query tag is public-table-valued. Rejecting ALL public
        // poles makes the honest abort decision independent of the witness.
        if self.tables.iter().any(|t| {
            (0..t.outputs.len()).any(|j| {
                let y = t.outputs.get(j);
                tag(
                    (i64::from(t.lower) + j as i64) as i16,
                    y,
                    t.profile + if y == t.outputs.overflow() { 60 } else { 0 },
                ) == alpha
            })
        }) {
            return Err("B12 lookup public pole".into());
        }
        Ok((
            descriptor,
            alpha,
            BindWork {
                frame_capacity_bytes: binding_frame_capacity_bytes,
                frame_logical_bytes: binding_frame_logical_bytes,
                attempt_encode_capacity_bytes,
                frame_capacity_while_attempt_live_bytes:
                    binding_frame_capacity_while_attempt_live_bytes,
                table_output_encoded_bytes: binding_table_output_encoded_bytes,
            },
        ))
    }

    fn leaf_constants_source(
        &self,
        descriptor: &Descriptor,
        point: &[Fp3],
        alpha: Fp3,
    ) -> (Fp3, Fp3, SourceWork) {
        let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
        let mut query = Fp3::ZERO;
        let mut denominator = Fp3::ZERO;
        let mut work = SourceWork::default();
        let (mul, sub, cap) = for_each_equality(point, |i, weight| {
            work.endpoint_leaf_reads += 1;
            match descriptor.row(i) {
                CompactRow::Query { profile, .. } => {
                    query += weight;
                    denominator += weight * (alpha - omega * omega * signed(i64::from(profile)));
                }
                CompactRow::Table(j) => {
                    denominator += weight * (alpha - table_tag(self, descriptor, j))
                }
                CompactRow::Padding => denominator += weight,
            }
        });
        work.equality_multiplications = mul;
        work.equality_subtractions = sub;
        work.eq_scratch_capacity_bytes = cap;
        (query, denominator, work)
    }
}

pub(super) fn prove(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i16),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    prove_wide_counted(
        s,
        |i| {
            let (x, y) = read_query(i);
            (x, i32::from(y))
        },
        read_histogram,
        false,
        fs,
        correlations,
    )
    .map(|(proof, pending, _)| (proof, pending))
}

pub(super) fn prove_wide(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i32),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    prove_wide_counted(s, read_query, read_histogram, true, fs, correlations)
        .map(|(proof, pending, _)| (proof, pending))
}

pub(super) fn prove_wide_counted(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i32),
    read_histogram: impl Fn(usize) -> i32,
    wide: bool,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Pending<Auth>, SourceWork), String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let (descriptor, alpha, bind_work) = s.bind(fs)?;
    let mut work = SourceWork::default();
    work.descriptor_capacity_bytes = descriptor.capacity_bytes();
    work.binding_frame_capacity_bytes = bind_work.frame_capacity_bytes;
    work.binding_frame_capacity_while_attempt_live_bytes =
        bind_work.frame_capacity_while_attempt_live_bytes;
    work.binding_frame_logical_bytes = bind_work.frame_logical_bytes;
    work.binding_table_output_encoded_bytes = bind_work.table_output_encoded_bytes;
    work.attempt_encode_capacity_bytes = bind_work.attempt_encode_capacity_bytes;
    work.rows_backing_capacity_bytes = 0;
    work.dimensions_transient_capacity_bytes =
        descriptor.dimensions_work.coverage_outer_capacity_bytes
            + descriptor.dimensions_work.coverage_inner_capacity_bytes
            + descriptor.dimensions_work.offsets_capacity_bytes;
    work.declared_subtree_stack_bytes = (1 << CutTree::CUT) * core::mem::size_of::<[Fp3; 2]>();
    // During the second child regeneration, the node array is nested under
    // the source-tree cubic accumulator, first child and folded sums. This is
    // source-visible payload, not a compiler/ABI stack-usage claim.
    work.declared_nested_stack_payload_lower_bound_bytes =
        work.declared_subtree_stack_bytes + 3 * core::mem::size_of::<[Fp3; 4]>();
    work.declared_stack_is_complete = false;
    work.correlation_rows_reserved = count as u64;
    work.correlation_rows_consumed = count as u64;
    work.correlation_row_copy_bytes = 0;
    work.binding_frame_payload_write_bytes = work.binding_frame_logical_bytes as u64;
    work.auth_size_bytes = core::mem::size_of::<Auth>();
    work.triple_size_bytes = core::mem::size_of::<[Auth; 3]>();
    work.layer_size_bytes = core::mem::size_of::<range::Layer>();
    work.compact_block_size_bytes = core::mem::size_of::<CompactBlock>();
    work.attempt_context_size_bytes = core::mem::size_of::<AttemptContext>();
    work.descriptor_size_bytes = core::mem::size_of::<Descriptor>();
    work.query_cache_size_bytes = core::mem::size_of::<QueryCache>();
    work.proof_size_bytes = core::mem::size_of::<Proof>();
    work.pending_auth_size_bytes = core::mem::size_of::<Pending<Auth>>();
    work.bind_work_size_bytes = core::mem::size_of::<BindWork>();
    work.dimension_work_size_bytes = core::mem::size_of::<DimensionWork>();
    work.source_work_size_bytes = core::mem::size_of::<SourceWork>();
    work.denominator_inversions = 1;
    work.denominator_zero_comparisons = 1;
    // `required` validates once before reserving correlations; `bind` builds
    // the descriptor and repeats the same fail-closed public validation.
    work.dimension_validation_passes = 2;
    work.dimension_table_metadata_visits = 6 * s.tables.len() as u64;
    work.dimension_block_visits = 2 * s.blocks.len() as u64;
    work.dimension_coverage_interval_visits =
        2 * s.blocks.iter().filter(|block| matches!(block, Block::Table { .. })).count() as u64;
    work.public_tag_scans = descriptor.rows as u64;
    let (queries, calls) = QueryCache::build(&descriptor, &read_query, wide)?;
    work.query_getter_calls = calls;
    work.query_cache_capacity_bytes = queries.capacity_bytes();
    let mut histogram = Vec::with_capacity(descriptor.rows);
    for j in 0..descriptor.rows {
        histogram.push(read_histogram(j));
    }
    work.histogram_getter_calls = descriptor.rows as u64;
    work.histogram_cache_capacity_bytes = histogram.capacity() * core::mem::size_of::<i32>();
    let leaf = |i| fraction_leaf(s, &descriptor, &queries, &histogram, alpha, i);
    let tree = CutTree::build(&leaf, descriptor.bits, &mut work);
    let denominator = tree.root()[1];
    if denominator == Fp3::ZERO {
        return Err("B12 lookup witness pole".into());
    }
    let (roots, root) = range::authenticate([denominator, denominator.inv()], &mut rows);
    fs.set_phase(0xd01);
    record_values(fs, 0xb1, &roots);
    let mut triples = vec![[root[0], root[1], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let replay = std::cell::Cell::new((0u64, 0u64));
    let (layers, point, claims, tree_work) = range::prove_tree_sourcewise(
        descriptor.bits,
        Vec::new(),
        [Auth::ZERO, root[0]],
        |layer, index| tree.children(layer, index, &leaf, &replay),
        fs,
        &mut rows,
        &mut triples,
    );
    work.tree = tree_work;
    (work.replay_leaf_reads, work.replay_reductions) = replay.get();
    work.proof_heap_capacity_bytes =
        range::tree_proof_heap_capacity_bytes(&layers, layers.capacity());
    work.proof_logical_heap_bytes = descriptor.bits * core::mem::size_of::<range::Layer>()
        + descriptor.bits.saturating_sub(1) * descriptor.bits / 2
            * core::mem::size_of::<[Fp3; 5]>();
    work.triples_capacity_bytes = triples.capacity() * core::mem::size_of::<[Auth; 3]>();
    work.triples_logical_bytes = triples.len() * core::mem::size_of::<[Auth; 3]>();
    work.point_capacity_bytes = point.capacity() * core::mem::size_of::<Fp3>();
    work.point_logical_bytes = point.len() * core::mem::size_of::<Fp3>();
    drop(tree);
    let mut values = [Fp3::ZERO; 3];
    let (mul, sub, eq_cap) = for_each_equality(&point, |i, weight| {
        work.endpoint_leaf_reads += 1;
        match descriptor.row(i) {
            CompactRow::Query { query, .. } => {
                let (x, y) = queries.get(query);
                values[0] += weight * signed(i64::from(x));
                values[1] += weight * signed(i64::from(y));
            }
            CompactRow::Table(j) => values[2] += weight * signed(i64::from(histogram[j])),
            CompactRow::Padding => {}
        }
    });
    work.equality_multiplications += mul;
    work.equality_subtractions += sub;
    work.eq_scratch_capacity_bytes = eq_cap;
    let retained = work.descriptor_capacity_bytes
        + work.query_cache_capacity_bytes
        + work.histogram_cache_capacity_bytes;
    let persistent = work.rows_backing_capacity_bytes + retained;
    let dimensions = work.rows_backing_capacity_bytes + work.dimensions_transient_capacity_bytes;
    let binding_payload = work.binding_frame_capacity_bytes.max(
        work.binding_frame_capacity_while_attempt_live_bytes + work.attempt_encode_capacity_bytes,
    );
    let binding =
        work.rows_backing_capacity_bytes + work.descriptor_capacity_bytes + binding_payload;
    let build = persistent + work.upper_tree_capacity_bytes;
    let replay = build
        + work.proof_heap_capacity_bytes
        + work.triples_capacity_bytes
        + work.tree.owned_regeneration_heap_peak_bytes;
    let endpoint = persistent
        + work.proof_heap_capacity_bytes
        + work.triples_capacity_bytes
        + work.point_capacity_bytes
        + work.eq_scratch_capacity_bytes;
    work.named_heap_peak_bytes = binding.max(build).max(endpoint);
    work.named_heap_peak_is_complete = false;
    work.owned_heap_peak_bytes = dimensions.max(binding).max(build).max(replay).max(endpoint);
    work.owned_capacity_is_complete = false;
    work.owned_heap_peak_excludes_external = true;
    let n = 1u64 << descriptor.bits;
    let replay_repetitions = work.replay_leaf_reads / n;
    let cache_payload = (if wide { 6 } else { 4 }) * descriptor.queries + 4 * descriptor.rows;
    work.cache_payload_write_bytes = cache_payload as u64;
    work.cache_payload_read_bytes = cache_payload as u64 * (2 + replay_repetitions);
    work.cache_query_decodes = descriptor.queries as u64 * (2 + replay_repetitions);
    work.cache_histogram_reads = descriptor.rows as u64 * (2 + replay_repetitions);
    work.public_table_output_reads = descriptor.rows as u64 * (3 + replay_repetitions);
    work.descriptor_row_calls = descriptor.live as u64 + 2 * n + work.replay_leaf_reads;
    let (wire, original) = range::authenticate(values, &mut rows);
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    let leaves = [
        wire[0],
        wire[1],
        wire[2],
        claims[0].m + original[2].m,
        claims[1].m + original[0].m + omega * original[1].m,
    ];
    fs.set_phase(0xd02);
    record_values(fs, 0xb2, &leaves);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    #[cfg(test)]
    eprintln!(
        "C71_LOOKUP_SOURCE_WORK {}",
        serde_json::json!({
        "query_rows":descriptor.queries,"table_rows":descriptor.rows,
        "query_width":if wide {6} else {4},"work":work})
    );
    Ok((Proof { roots, layers, leaves, products }, Pending { point, originals: original }, work))
}

#[cfg(test)]
fn prove_wide_dense_oracle(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i32),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (descriptor, alpha, _bind_work) = s.bind(fs)?;
    let (tags, domain) = s.public()?;
    debug_assert_eq!(descriptor.live, domain.len());
    let bits = domain.len().next_power_of_two().ilog2() as usize;
    // ponytail: dense domain/tree within the analytic resource envelope.
    // Physical Gemma admission still requires the subtree replay schedule.
    let mut bottom = vec![[Fp3::ZERO, Fp3::ONE]; 1 << bits];
    for (i, &row) in domain.iter().enumerate() {
        bottom[i] = match row {
            Row::Query(profile) => {
                let (x, y) = read_query(i);
                [Fp3::ONE, alpha - tag(x, y, profile)]
            }
            Row::Table(j) => [-signed(i64::from(read_histogram(j))), alpha - tags[j]],
        };
    }
    let mut tree = vec![bottom];
    while tree.last().unwrap().len() > 1 {
        tree.push(
            tree.last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let ([p, q], [r, s]) = (pair[0], pair[1]);
                    [p * s + r * q, q * s]
                })
                .collect(),
        );
    }
    let denominator = tree.last().unwrap()[0][1];
    if denominator == Fp3::ZERO {
        return Err("B12 lookup witness pole".into());
    }
    let (roots, root) = range::authenticate([denominator, denominator.inv()], &mut rows);
    fs.set_phase(0xd01);
    record_values(fs, 0xb1, &roots);
    let mut triples = vec![[root[0], root[1], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let (layers, point, claims) =
        range::prove_tree(&tree, Vec::new(), [Auth::ZERO, root[0]], fs, &mut rows, &mut triples);
    let weights = eq(&point);
    let mut values = [Fp3::ZERO; 3];
    for (i, &row) in domain.iter().enumerate() {
        match row {
            Row::Query(_) => {
                let (x, y) = read_query(i);
                values[0] += weights[i] * signed(i64::from(x));
                values[1] += weights[i] * signed(i64::from(y));
            }
            Row::Table(j) => values[2] += weights[i] * signed(i64::from(read_histogram(j))),
        }
    }
    let (wire, original) = range::authenticate(values, &mut rows);
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    let leaves = [
        wire[0],
        wire[1],
        wire[2],
        claims[0].m + original[2].m,
        claims[1].m + original[0].m + omega * original[1].m,
    ];
    fs.set_phase(0xd02);
    record_values(fs, 0xb2, &leaves);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    Ok((Proof { roots, layers, leaves, products }, Pending { point, originals: original }))
}

pub(super) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<Pending<Key>, String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let (descriptor, alpha, _bind_work) = s.bind(fs)?;
    let bits = descriptor.bits;
    if !range::tree_shape(&proof.layers, bits, 0) {
        return Err("B12 lookup tree shape differs".into());
    }
    let root = range::correct(proof.roots, delta, &mut rows);
    fs.set_phase(0xd01);
    record_values(fs, 0xb1, &proof.roots);
    let mut triples = vec![[root[0], root[1], Key::new(delta)]];
    let (point, claims) = range::verify_tree(
        &proof.layers,
        Vec::new(),
        [Key::ZERO, root[0]],
        delta,
        fs,
        &mut rows,
        &mut triples,
    )?;
    let original =
        range::correct([proof.leaves[0], proof.leaves[1], proof.leaves[2]], delta, &mut rows);
    let (query, denominator, _source_work) = s.leaf_constants_source(&descriptor, &point, alpha);
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    if claims[0].k + original[2].k - delta * query != proof.leaves[3]
        || claims[1].k + original[0].k + omega * original[1].k - delta * denominator
            != proof.leaves[4]
    {
        return Err("B12 lookup original leaf MAC rejected".into());
    }
    fs.set_phase(0xd02);
    record_values(fs, 0xb2, &proof.leaves);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    debug_assert!(rows.next().is_none());
    Ok(Pending { point, originals: original })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::{RngExt, SeedableRng};

    fn source(xy: &[(i16, i16)], m: &[i32]) -> Vec<i16> {
        let mut bytes = Vec::new();
        for lane in 0..2 {
            for &(x, y) in xy {
                let x = if lane == 0 { x } else { y };
                bytes.extend(
                    (i32::from(x) + 32768).to_le_bytes()[..2].iter().map(|&b| i16::from(b)),
                );
            }
        }
        for &x in m {
            bytes.extend(
                (i64::from(x) + (1 << 31)).to_le_bytes()[..4].iter().map(|&b| i16::from(b)),
            );
        }
        bytes.resize(1024, 0);
        bytes
    }

    fn positions(s: &Statement<'_>) -> ([usize; 4], [usize; 6]) {
        let (_, domain) = s.public().unwrap();
        let (mut query, mut table, mut next) = ([0; 4], [0; 6], 0);
        for (i, row) in domain.into_iter().enumerate() {
            match row {
                Row::Query(_) => {
                    query[next] = i;
                    next += 1;
                }
                Row::Table(j) => table[j] = i,
            }
        }
        (query, table)
    }

    fn forms(s: &Statement<'_>, point: &[Fp3]) -> ([Vec<Cube>; 3], [Fp3; 3]) {
        let weights = eq(point);
        let (query, table) = positions(s);
        let mut shifts = [Fp3::ZERO; 3];
        let forms = std::array::from_fn(|lane| {
            let (offset, count, bytes) = [(0, 4, 2), (8, 4, 2), (16, 6, 4)][lane];
            let mut form = Vec::new();
            for i in 0..count {
                let coefficient = weights[if lane < 2 { query[i] } else { table[i] }];
                shifts[lane] += coefficient * signed(1 << (8 * bytes - 1));
                for b in 0..bytes {
                    form.push(Cube {
                        offset: offset + bytes * i + b,
                        point: Vec::new(),
                        coefficient: coefficient * signed(1 << (8 * b)),
                    });
                }
            }
            form
        });
        (forms, shifts)
    }

    #[test]
    fn c71_b12_lookup_rejects_wrong_gelu_overflow_and_detached_original_histogram() {
        // Certified scalar vectors from C71-GELU-RNE-v1 at input -1,0,1:
        // exponents (0,0) and (0,-16). This is a restricted-domain component,
        // not a calibrated full Gemma table or a producer-RNE proof.
        let tables = [
            Table { profile: 0, lower: -1, outputs: Outputs::I16(&[0, 0, 1]) },
            Table { profile: 1, lower: -1, outputs: Outputs::I16(&[-10408, 0, i16::MIN]) },
        ];
        let blocks = [
            Block::Table { index: 1, first: 1, len: 2 },
            Block::Query { profile: 0, len: 1 },
            Block::Table { index: 0, first: 0, len: 3 },
            Block::Query { profile: 1, len: 1 },
            Block::Query { profile: 0, len: 1 },
            Block::Table { index: 1, first: 0, len: 1 },
            Block::Query { profile: 1, len: 1 },
        ];
        let honest = [(-1, 0), (-1, -10408), (1, 1), (0, 0)];
        let histogram = [1, 0, 1, 1, 1, 0];
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = [64; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        for fault in 0..4 {
            let mut used = honest;
            let mut counts = histogram;
            if fault == 1 {
                used[0].1 = 1;
            }
            if fault == 2 {
                used[0].0 = 0; // same rounded Y; update histogram consistently
                counts[0] = 0;
                counts[1] = 1;
            }
            if fault == 3 {
                used[3] = (1, i16::MIN);
                counts[4] = 0;
                counts[5] = 1; // overflow row has profile 61, NEVER query 1
            }
            let model = Model::new(
                32,
                if fault == 2 { source(&honest, &histogram) } else { source(&used, &counts) },
            )
            .unwrap();
            let s = Statement {
                root: &model.root,
                profile: &profile,
                view: layout,
                attempt,
                blocks: &blocks,
                tables: &tables,
            };
            assert_eq!(s.required().unwrap(), 58);
            let (query_positions, _) = positions(&s);
            assert_eq!(query_positions, [2, 6, 7, 9]);
            let count = s.required().unwrap() + 510 + 32;
            assert_eq!(count, 600);
            let mut rng = MatrixRng::from_seed([149; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"lookup original query and histogram bytes", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (proof, p) = prove(
                &s,
                |i| used[query_positions.iter().position(|&p| p == i).unwrap()],
                |j| counts[j],
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(fs.requests(), 16);
            let (range_proof, ranges, targets) = range::prove(
                &model,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (extra, shifts) = forms(&s, &p.point);
            let all_forms: Vec<_> = ranges.into_iter().chain(extra).collect();
            let all_targets: Vec<_> = targets
                .into_iter()
                .chain(p.originals.into_iter().zip(shifts).map(|(a, s)| Auth::new(a.x + s, a.m)))
                .collect();
            let (pcs, digest) = linear::prove(
                &model,
                attempt,
                layout,
                &all_forms,
                &all_targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let result = verify(&s, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 || fault == 3 {
                assert!(result.is_err(), "invalid lookup or overflow passed its GKR");
                continue;
            }
            let p = result.unwrap();
            assert_eq!(fs.requests(), 16);
            let (ranges, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (extra, shifts) = forms(&s, &p.point);
            let all_forms: Vec<_> = ranges.into_iter().chain(extra).collect();
            let all_targets: Vec<_> = targets
                .into_iter()
                .chain(p.originals.into_iter().zip(shifts).map(|(k, s)| Key::new(k.k + delta * s)))
                .collect();
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                layout,
                &all_forms,
                &all_targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert_eq!(result.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                assert!(vrows.len() > 0);
            } else {
                assert_eq!(result.unwrap(), digest);
                assert!(vrows.next().is_none());
            }
        }
        let root = C61Commitment::new(vec![[1; 32]]);
        let s = Statement {
            root: &root,
            profile: &profile,
            view: layout,
            attempt,
            blocks: &blocks,
            tables: &tables,
        };
        let mut exhausted = vec![Auth::ZERO; 57].into_iter();
        assert!(prove(
            &s,
            |_| panic!("exhaustion read witness"),
            |_| panic!("exhaustion read histogram"),
            &mut Fs::new(b"exhausted lookup", 100),
            &mut exhausted
        )
        .is_err());
        assert_eq!(exhausted.len(), 57);
        let mut wrong = Statement { blocks: &[Block::Query { profile: 60, len: 1 }], ..s };
        assert!(wrong.required().is_err());
        wrong.blocks = &[Block::Query { profile: 2, len: 1 }];
        assert!(wrong.required().is_err());
        wrong.blocks =
            &[Block::Query { profile: 0, len: 1 }, Block::Table { index: 0, first: 0, len: 3 }];
        assert!(wrong.required().is_err());
        wrong.blocks = &[
            Block::Query { profile: 0, len: 1 },
            Block::Table { index: 0, first: 0, len: 3 },
            Block::Table { index: 0, first: 0, len: 3 },
            Block::Table { index: 1, first: 0, len: 3 },
        ];
        assert!(wrong.required().is_err());
        assert_ne!(tag(1, i32::from(i16::MIN), 1), tag(1, i32::from(i16::MIN), 61));
    }

    #[test]
    fn source_lookup_matches_dense_wire_transcript_endpoint_and_exact_cache_widths() {
        use crate::c71_matrix::wire::Wire;
        let narrow = [10i16, 20, 30];
        let tables = [Table { profile: 0, lower: -1, outputs: Outputs::I16(&narrow) }];
        let blocks = [
            Block::Query { profile: 0, len: 30 },
            Block::Table { index: 0, first: 0, len: 1 },
            Block::Query { profile: 0, len: 30 },
            Block::Table { index: 0, first: 1, len: 2 },
        ];
        let profile = gamma(&matrix_config(32).unwrap());
        let root = C61Commitment::new(vec![[7; 32]]);
        let statement = Statement {
            root: &root,
            profile: &profile,
            view: [64; 32],
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [3; 32],
                nonce: [4; 32],
            },
            blocks: &blocks,
            tables: &tables,
        };
        let histogram = [20, 20, 20];
        let descriptor = Descriptor::new(&statement).unwrap();
        let (dense_tags, dense_domain) = statement.public().unwrap();
        for point in [
            vec![Fp3::ZERO; descriptor.bits],
            vec![Fp3::ONE; descriptor.bits],
            (0..descriptor.bits)
                .map(|i| {
                    Fp3::new(
                        Fp::new((i + 2) as u64),
                        Fp::new((i + 7) as u64),
                        Fp::new((i + 11) as u64),
                    )
                })
                .collect(),
        ] {
            let alpha = Fp3::new(Fp::new(17), Fp::new(19), Fp::new(23));
            let weights = eq(&point);
            let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
            let mut expected = (Fp3::ZERO, Fp3::ZERO);
            for (i, weight) in weights.into_iter().enumerate() {
                match dense_domain.get(i) {
                    Some(Row::Query(profile)) => {
                        expected.0 += weight;
                        expected.1 +=
                            weight * (alpha - omega * omega * signed(i64::from(*profile)));
                    }
                    Some(Row::Table(j)) => expected.1 += weight * (alpha - dense_tags[*j]),
                    None => expected.1 += weight,
                }
            }
            let (query, denominator, _) =
                statement.leaf_constants_source(&descriptor, &point, alpha);
            assert_eq!((query, denominator), expected);
        }
        let positions: Vec<_> = (0..descriptor.live)
            .filter(|&i| matches!(descriptor.row(i), CompactRow::Query { .. }))
            .collect();
        let get = |i| {
            let ordinal = positions.iter().position(|&x| x == i).unwrap();
            let x = (ordinal % 3) as i16 - 1;
            (x, narrow[(x + 1) as usize] as i32)
        };
        let count = statement.required().unwrap();
        let delta = Fp3::new(Fp::new(3), Fp::new(5), Fp::new(9));
        let mut rng = MatrixRng::from_seed([91; 32]);
        let auth: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = auth.iter().map(|row| Key::new(row.m + delta * row.x)).collect();
        let start = || Fs::new(b"lookup source dense identity", 100_000);
        let mut dense_fs = start();
        let mut dense_rows = auth.clone().into_iter();
        let (dense, dense_pending) = prove_wide_dense_oracle(
            &statement,
            get,
            |j| histogram[j],
            &mut dense_fs,
            &mut dense_rows,
        )
        .unwrap();
        let mut source_fs = start();
        let requested = std::cell::Cell::new(0);
        let mut source_rows = auth.into_iter().inspect(|_| requested.set(requested.get() + 1));
        let (source, source_pending, work) = prove_wide_counted(
            &statement,
            |index| {
                assert_eq!(requested.get(), 0);
                get(index)
            },
            |index| {
                assert_eq!(requested.get(), 0);
                histogram[index]
            },
            false,
            &mut source_fs,
            &mut source_rows,
        )
        .unwrap();
        assert_eq!(requested.get(), count);
        let mut verifier_fs = start();
        let mut verifier_rows = keys.into_iter();
        let verified =
            verify(&statement, &source, delta, &mut verifier_fs, &mut verifier_rows).unwrap();
        assert_eq!(verifier_rows.len(), 0);
        assert_eq!(verified.point, source_pending.point);
        assert_eq!(
            verified.originals.map(|key| key.k),
            source_pending.originals.map(|row| row.m + delta * row.x)
        );
        assert_eq!(verifier_fs.digest(), source_fs.digest());
        let mut dense_wire = Vec::new();
        dense.write(&mut dense_wire);
        let mut source_wire = Vec::new();
        source.write(&mut source_wire);
        assert_eq!(source_wire, dense_wire);
        assert_eq!(source_pending.point, dense_pending.point);
        assert_eq!(
            source_pending.originals.map(|a| (a.x, a.m)),
            dense_pending.originals.map(|a| (a.x, a.m))
        );
        assert_eq!(source_fs.requests(), dense_fs.requests());
        assert_eq!(source_fs.fp3(), dense_fs.fp3());
        assert_eq!(source_rows.len(), dense_rows.len());
        assert_eq!(core::mem::size_of::<[u8; 4]>(), 4);
        assert!(work.query_cache_capacity_bytes >= 4 * positions.len());
        assert!(work.histogram_cache_capacity_bytes >= 4 * histogram.len());
        assert_eq!(work.query_getter_calls, positions.len() as u64);
        assert_eq!(work.histogram_getter_calls, histogram.len() as u64);
        assert!(work.upper_tree_capacity_bytes < 48 * ((1usize << descriptor.bits) * 2 - 1));
        let n = 1usize << descriptor.bits;
        let replay_repetitions: usize =
            (descriptor.bits - CutTree::CUT..descriptor.bits).map(|layer| layer + 1).sum();
        assert_eq!(work.dimension_validation_passes, 2);
        assert_eq!(work.dimension_table_metadata_visits, 6 * tables.len() as u64);
        assert_eq!(work.dimension_block_visits, 2 * blocks.len() as u64);
        assert_eq!(work.dimension_coverage_interval_visits, 4);
        assert_eq!(work.correlation_rows_reserved, count as u64);
        assert_eq!(work.correlation_rows_consumed, count as u64);
        assert_eq!(work.correlation_row_copy_bytes, 0);
        assert_eq!(
            work.cache_payload_write_bytes,
            (4 * positions.len() + 4 * histogram.len()) as u64
        );
        assert_eq!(
            work.cache_payload_read_bytes,
            ((4 * positions.len() + 4 * histogram.len()) * (2 + replay_repetitions)) as u64
        );
        assert_eq!(work.binding_frame_payload_write_bytes, work.binding_frame_logical_bytes as u64);
        assert_eq!(work.rows_backing_capacity_bytes, 0);
        assert_eq!(
            work.proof_logical_heap_bytes,
            range::tree_proof_logical_heap_bytes(descriptor.bits, 0)
        );
        assert!(work.proof_heap_capacity_bytes >= work.proof_logical_heap_bytes);
        assert_eq!(work.triples_logical_bytes, (1 + 3 * descriptor.bits) * 144);
        assert!(work.triples_capacity_bytes >= work.triples_logical_bytes);
        assert_eq!(work.point_logical_bytes, descriptor.bits * 24);
        assert!(work.point_capacity_bytes >= work.point_logical_bytes);
        assert!(work.binding_frame_capacity_bytes >= work.binding_frame_logical_bytes);
        assert!(work.attempt_encode_capacity_bytes >= 130);
        assert_eq!(work.declared_subtree_stack_bytes, 16 * 48);
        assert_eq!(work.declared_nested_stack_payload_lower_bound_bytes, 16 * 48 + 3 * 96);
        assert_eq!(work.cache_query_decodes, (positions.len() * (2 + replay_repetitions)) as u64);
        assert_eq!(work.cache_histogram_reads, (histogram.len() * (2 + replay_repetitions)) as u64);
        assert_eq!(
            work.public_table_output_reads,
            (histogram.len() * (3 + replay_repetitions)) as u64
        );
        assert_eq!(
            work.descriptor_row_calls,
            (descriptor.live + 2 * n + n * replay_repetitions) as u64
        );
        let simultaneous_replay_lower = work.rows_backing_capacity_bytes
            + work.descriptor_capacity_bytes
            + work.query_cache_capacity_bytes
            + work.histogram_cache_capacity_bytes
            + work.upper_tree_capacity_bytes
            + work.proof_heap_capacity_bytes
            + work.triples_capacity_bytes;
        assert!(work.owned_heap_peak_bytes >= simultaneous_replay_lower);
        assert!(!work.owned_capacity_is_complete);
        assert!(work.owned_heap_peak_excludes_external);
        assert!(!work.declared_stack_is_complete);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(work.auth_size_bytes, 48);
            assert_eq!(work.triple_size_bytes, 144);
            assert_eq!(work.layer_size_bytes, 216);
            assert_eq!(work.compact_block_size_bytes, 32);
            assert_eq!(work.attempt_context_size_bytes, 129);
            assert_eq!(work.descriptor_size_bytes, 104);
            assert_eq!(work.query_cache_size_bytes, 32);
            assert_eq!(work.proof_size_bytes, 240);
            assert_eq!(work.pending_auth_size_bytes, 168);
            assert_eq!(work.bind_work_size_bytes, 40);
            assert_eq!(work.dimension_work_size_bytes, 24);
            assert!(work.source_work_size_bytes >= 40 * core::mem::size_of::<usize>());
        }

        let wide_values = [70_000i32];
        let wide_tables = [Table { profile: 0, lower: 0, outputs: Outputs::I32(&wide_values) }];
        let wide_blocks = [
            Block::Query { profile: 0, len: 32 },
            Block::Table { index: 0, first: 0, len: 1 },
            Block::Query { profile: 0, len: 32 },
        ];
        let wide_statement = Statement { blocks: &wide_blocks, tables: &wide_tables, ..statement };
        let wide_descriptor = Descriptor::new(&wide_statement).unwrap();
        let (cache, calls) = QueryCache::build(&wide_descriptor, &|_| (0, 70_000), true).unwrap();
        assert_eq!(calls, 64);
        assert_eq!(core::mem::size_of::<[u8; 6]>(), 6);
        assert!(cache.capacity_bytes() >= 6 * 64);
        assert_eq!(cache.get(63), (0, 70_000));
        assert!(QueryCache::build(&wide_descriptor, &|_| (0, 70_000), false).is_err());
        let wide_count = wide_statement.required().unwrap();
        let mut rng = MatrixRng::from_seed([92; 32]);
        let wide_auth: Vec<_> = (0..wide_count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let wide_start = || Fs::new(b"lookup wide source dense identity", 100_000);
        let mut dense_fs = wide_start();
        let mut dense_rows = wide_auth.clone().into_iter();
        let (dense, dense_pending) = prove_wide_dense_oracle(
            &wide_statement,
            |_| (0, 70_000),
            |_| 64,
            &mut dense_fs,
            &mut dense_rows,
        )
        .unwrap();
        let mut source_fs = wide_start();
        let mut source_rows = wide_auth.into_iter();
        let (source, source_pending_wide, wide_work) = prove_wide_counted(
            &wide_statement,
            |_| (0, 70_000),
            |_| 64,
            true,
            &mut source_fs,
            &mut source_rows,
        )
        .unwrap();
        let mut dense_wire = Vec::new();
        dense.write(&mut dense_wire);
        let mut source_wire = Vec::new();
        source.write(&mut source_wire);
        assert_eq!(source_wire, dense_wire);
        assert_eq!(source_pending_wide.point, dense_pending.point);
        assert_eq!(
            source_pending_wide.originals.map(|a| (a.x, a.m)),
            dense_pending.originals.map(|a| (a.x, a.m))
        );
        assert_eq!(source_fs.fp3(), dense_fs.fp3());
        assert_eq!(source_rows.len(), dense_rows.len());
        assert!(wide_work.query_cache_capacity_bytes >= 6 * 64);
        let keys: Vec<_> =
            source_pending.originals.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        assert_eq!(keys.len(), 3); // The original authenticated endpoint is unchanged.
    }
}

//! Public i16-input lookup, with X/Y and the fixed histogram in the SAME source.
//! Reuses range's fraction GKR; it does not commit inverses or a trace.

use super::*;

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
    fn public(&self) -> Result<(Vec<Fp3>, Vec<Row>), String> {
        if self.blocks.is_empty()
            || self.blocks.len() > 65791
            || self.tables.is_empty()
            || self.tables.len() > 60
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 lookup fixed context or native query cap differs".into());
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
        if rows > 65535 {
            return Err("B12 lookup public row cap differs".into());
        }
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
        let mut coverage = vec![Vec::new(); self.tables.len()];
        let mut queries = 0usize;
        let mut offsets = Vec::new();
        let mut offset = 0;
        for t in self.tables {
            offsets.push(offset);
            offset += t.outputs.len();
        }
        // Validate compact blocks BEFORE expanding this bounded native view.
        for &block in self.blocks {
            match block {
                Block::Query { profile, len } => {
                    if profile >= 60 || !seen[profile as usize] || len == 0 || len > 256 {
                        return Err("B12 lookup query block differs".into());
                    }
                    queries += len;
                    if queries > 256 {
                        return Err("B12 lookup native query cap exceeded".into());
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
        Ok(required(self.public()?.1.len().next_power_of_two().ilog2() as usize))
    }

    fn bind(&self, fs: &mut Fs) -> Result<(Vec<Fp3>, Vec<Row>, Fp3), String> {
        let (tags, domain) = self.public()?;
        let wide = self.tables.iter().any(|t| matches!(t.outputs, Outputs::I32(_)));
        let mut bytes = if wide {
            b"C71-lookup-B12-v3;i16-input;typed-i16-i32-output;MIN-overflow;original-A".to_vec()
        } else {
            b"C71-lookup-B12-v2;fixed-X-Y-M;public-blocks;overflow-profile-plus-60;original-A"
                .to_vec()
        };
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
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
            t.outputs.encode(&mut bytes);
        }
        fs.set_phase(0xd00);
        fs.record(0xb0, &bytes);
        let alpha = fs.fp3();
        // Every honest query tag is public-table-valued. Rejecting ALL public
        // poles makes the honest abort decision independent of the witness.
        if tags.contains(&alpha) {
            return Err("B12 lookup public pole".into());
        }
        Ok((tags, domain, alpha))
    }

    fn leaf_constants(
        &self,
        tags: &[Fp3],
        domain: &[Row],
        point: &[Fp3],
        alpha: Fp3,
    ) -> (Fp3, Fp3) {
        let weights = eq(point);
        let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
        let mut query = Fp3::ZERO;
        let mut denominator = Fp3::ZERO;
        for (i, &weight) in weights.iter().enumerate() {
            match domain.get(i) {
                Some(&Row::Query(profile)) => {
                    query += weight;
                    denominator += weight * (alpha - omega * omega * signed(i64::from(profile)));
                }
                Some(&Row::Table(j)) => denominator += weight * (alpha - tags[j]),
                None => denominator += weight,
            }
        }
        (query, denominator)
    }
}

pub(super) fn prove(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i16),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    prove_wide(
        s,
        |i| {
            let (x, y) = read_query(i);
            (x, i32::from(y))
        },
        read_histogram,
        fs,
        correlations,
    )
}

pub(super) fn prove_wide(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i32),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (tags, domain, alpha) = s.bind(fs)?;
    let bits = domain.len().next_power_of_two().ilog2() as usize;
    // ponytail: dense D<=17 component. Full Gemma needs the documented
    // subtree replay schedule and canonical source caller, not this array.
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
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<Pending<Key>, String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (tags, domain, alpha) = s.bind(fs)?;
    let bits = domain.len().next_power_of_two().ilog2() as usize;
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
    let (query, denominator) = s.leaf_constants(&tags, &domain, &point, alpha);
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
            } else {
                assert_eq!(result.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
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
}

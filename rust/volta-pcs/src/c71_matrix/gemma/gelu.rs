//! Canonical GELU inputs/outputs/histograms in the SAME P0/RMS byte source.
//! Compact dispatch takes certified public tables; full execution is separate.

use super::caller::P0Statement;
use super::rms::prefix as point;
use super::*;
use crate::c71_matrix::lookup::Block;
use crate::c71_matrix::{lookup, Auth, Fs, Key};

pub(in crate::c71_matrix) struct Gelu {
    pub layer: u8,
    pub raw_gate: usize,
    pub input: usize,
    pub output: usize,
    pub histogram: usize,
    pub rows: usize,
    pub columns: usize,
}

pub(in crate::c71_matrix) struct Sources {
    pub rms: rms::Sources,
    pub gelu: Vec<Gelu>,
    pub cells: usize,
    pub queries: usize,
    pub view: [u8; 32],
    tiles: Vec<Tile>,
}

pub(in crate::c71_matrix) enum Cell {
    Query { gelu: usize, row: usize, column: usize },
    Histogram { gelu: usize, entry: usize },
}

impl Plan {
    pub fn gelu_sources(&self) -> Result<Sources, String> {
        let rms = self.rms_sources()?;
        let base = rms.bytes.scalar.layout.sources.len();
        let gates: Vec<_> =
            self.cohorts.iter().enumerate().filter(|(_, c)| c.operation == "gate_proj").collect();
        if gates.is_empty() || gates.len() > 60 {
            return Err("GELU gate cohorts missing".into());
        }
        let mut layers = std::collections::BTreeSet::new();
        let mut extra = Vec::new();
        let mut gelu = Vec::new();
        // Keep the raw C IDs and old RMS/P0 source IDs. X is explicitly in
        // A, so a full-table RNE proof must tie it to its original gate C.
        for (i, &(raw, c)) in gates.iter().enumerate() {
            let layer = c.layer.ok_or("GELU gate layer missing")?;
            if layer >= 60
                || !layers.insert(layer)
                || c.kind != Kind::Matrix
                || c.rows == 0
                || c.columns == 0
            {
                return Err("GELU gate profile or shape differs".into());
            }
            extra.push((format!("X/{layer}/gate_proj"), c.rows, c.columns, 2));
            gelu.push(Gelu {
                layer: layer as u8,
                raw_gate: raw,
                input: base + i,
                output: base + gates.len() + i,
                histogram: base + 2 * gates.len() + i,
                rows: c.rows,
                columns: c.columns,
            });
        }
        for g in &gelu {
            extra.push((format!("X/{}/gelu_tanh", g.layer), g.rows, g.columns, 2));
        }
        for g in &gelu {
            extra.push((format!("M/GELU/{}", g.layer), 1, 65535, 4));
        }
        let rms = rms.append(extra)?;
        let mut word_sources: Vec<_> = gelu
            .iter()
            .map(|g| Source {
                name: format!("GELU/query/{}", g.layer),
                rows: g.rows,
                cols: g.columns,
                packed_offset: 0,
            })
            .collect();
        word_sources.extend(gelu.iter().map(|g| Source {
            name: format!("GELU/table/{}", g.layer),
            rows: 1,
            cols: 65535,
            packed_offset: 0,
        }));
        let (tiles, cells) = tiles(&word_sources);
        let queries = gelu.iter().map(|g| g.rows * g.columns).sum();
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-GELU-source-view-v1;query-table-dyadic-tiles;original-X-Y-M\0");
        digest.update(&rms.bytes.layout_digest);
        digest.update(&(gelu.len() as u64).to_le_bytes());
        for g in &gelu {
            for v in [
                usize::from(g.layer),
                g.raw_gate,
                g.input,
                g.output,
                g.histogram,
                g.rows,
                g.columns,
            ] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        for t in &tiles {
            for v in [t.tensor, t.row, t.col, t.rows, t.cols, t.offset] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        Ok(Sources { rms, gelu, cells, queries, view: *digest.finalize().as_bytes(), tiles })
    }
}

impl Sources {
    fn bind_lookup_context(
        &self,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
        fs: &mut Fs,
    ) -> Result<(), String> {
        if tables.len() != self.gelu.len()
            || tables
                .iter()
                .zip(&self.gelu)
                .any(|(t, g)| t.profile != g.layer || t.lower != -32767 || t.outputs.len() != 65535)
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.auxiliary_layout.weight_layout != self.rms.bytes.scalar.weight_layout
            || s.auxiliary_layout.layout.layout_digest != self.rms.bytes.scalar.layout.layout_digest
        {
            return Err("GELU canonical table or fixed source context differs".into());
        }
        // Tables are the verifier's certified public profile. Shape and
        // digest binding alone do not certify that an arbitrary table is GELU.
        let mut bytes = b"C71-canonical-GELU-B12-v1;original-gate-X-Y-M\0".to_vec();
        bytes.extend(s.weights.roots()[0]);
        bytes.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            bytes.extend((gamma.len() as u64).to_le_bytes());
            bytes.extend(gamma);
        }
        bytes.extend(s.quantization);
        bytes.extend(s.attempt.encode());
        bytes.extend(self.view);
        fs.set_phase(0xf00);
        fs.record(0xd0, &bytes);
        Ok(())
    }

    pub fn prove_lookup(
        &self,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
        read: impl Fn(usize, usize, usize, usize) -> u8,
        fs: &mut Fs,
        rows: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(lookup::Proof, lookup::Pending<Auth>), String> {
        self.bind_lookup_context(s, tables, fs)?;
        let blocks = self.blocks();
        let statement = lookup::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.view,
            attempt: s.attempt,
            blocks: &blocks,
            tables,
        };
        lookup::prove(
            &statement,
            |i| {
                let Some(Cell::Query { gelu, row, column }) = self.cell(i).unwrap() else {
                    unreachable!("public lookup block is not a query")
                };
                let g = &self.gelu[gelu];
                let word = |source| {
                    (i32::from(u16::from_le_bytes([
                        read(source, row, column, 0),
                        read(source, row, column, 1),
                    ])) - 32768) as i16
                };
                (word(g.input), word(g.output))
            },
            |j| {
                let g = &self.gelu[j / 65535];
                let biased =
                    u32::from_le_bytes(std::array::from_fn(|b| read(g.histogram, 0, j % 65535, b)));
                (i64::from(biased) - (1 << 31)) as i32
            },
            fs,
            rows,
        )
    }

    pub fn verify_lookup(
        &self,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
        proof: &lookup::Proof,
        delta: Fp3,
        fs: &mut Fs,
        rows: &mut std::vec::IntoIter<Key>,
    ) -> Result<lookup::Pending<Key>, String> {
        self.bind_lookup_context(s, tables, fs)?;
        let blocks = self.blocks();
        lookup::verify(
            &lookup::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view: self.view,
                attempt: s.attempt,
                blocks: &blocks,
                tables,
            },
            proof,
            delta,
            fs,
            rows,
        )
    }

    pub fn gate_rne_pairs(&self, shifts: &[i32]) -> Result<Vec<bytes::quantize::Pair>, String> {
        if shifts.len() != self.gelu.len() {
            return Err("GELU gate shift profile differs".into());
        }
        Ok(self
            .gelu
            .iter()
            .zip(shifts)
            .map(|(g, &shift)| bytes::quantize::Pair { raw: g.raw_gate, output: g.input, shift })
            .collect())
    }

    pub fn blocks(&self) -> Vec<Block> {
        self.tiles
            .iter()
            .map(|t| {
                if t.tensor < self.gelu.len() {
                    Block::Query { profile: self.gelu[t.tensor].layer, len: t.rows * t.cols }
                } else {
                    Block::Table { index: t.tensor - self.gelu.len(), first: t.col, len: t.cols }
                }
            })
            .collect()
    }

    pub fn cell(&self, index: usize) -> Result<Option<Cell>, String> {
        if index >= self.cells.next_power_of_two() {
            return Err("GELU cell exceeds padded domain".into());
        }
        if index >= self.cells {
            return Ok(None);
        }
        let t = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let local = index - t.offset;
        Ok(Some(if t.tensor < self.gelu.len() {
            Cell::Query {
                gelu: t.tensor,
                row: t.row + local / t.cols,
                column: t.col + local % t.cols,
            }
        } else {
            Cell::Histogram { gelu: t.tensor - self.gelu.len(), entry: t.col + local }
        }))
    }

    /// The lookup's three ORIGINAL X/Y/M MACs, including their affine byte
    /// bias. Global query/table order comes from the same public word tiles.
    pub fn forms(&self, p: &[Fp3]) -> Result<([Vec<Cube>; 3], [Fp3; 3]), String> {
        let cb = bits(self.cells);
        if p.len() != cb {
            return Err("GELU original lookup point differs".into());
        }
        let mut forms: [Vec<Cube>; 3] = std::array::from_fn(|_| Vec::new());
        let mut shifts = [Fp3::ZERO; 3];
        for t in &self.tiles {
            let local = bits(t.rows) + bits(t.cols);
            let coefficient = eq_index(&p[..cb - local], t.offset / (t.rows * t.cols));
            if coefficient == Fp3::ZERO {
                continue;
            }
            let index = t.tensor % self.gelu.len();
            let g = &self.gelu[index];
            let query = t.tensor < self.gelu.len();
            let rp = point(
                t.row,
                t.rows,
                if query { g.rows } else { 1 },
                &p[cb - local..cb - bits(t.cols)],
            );
            let cp = point(
                t.col,
                t.cols,
                if query { g.columns } else { 65535 },
                &p[cb - bits(t.cols)..],
            );
            for (lane, source) in [(0, g.input), (1, g.output), (2, g.histogram)] {
                if (lane < 2) != query {
                    continue;
                }
                let (form, shift) = self.rms.bytes.word_form(source, &rp, &cp, coefficient)?;
                forms[lane].extend(form);
                shifts[lane] += shift;
            }
        }
        Ok((forms, shifts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{eq, signed};
    use crate::c71_matrix::{
        from_p3, gamma, matrix_config, AttemptContext, C61Commitment, MatrixRng, E,
    };
    use rand_010::{RngExt, SeedableRng};

    fn canonical_lookup_and_gate_rne(source: &Sources, plan: &Plan) {
        // Full public GELU table for the SPECIAL integer profile (0,0).
        // Equality with the certified generator is checked in Python. This
        // identity does not replace GELU by ReLU for any other profile.
        let outputs: Vec<i16> = (-32767i32..=32767).map(|x| x.max(0) as i16).collect();
        let tables = [lookup::Table { profile: 0, lower: -32767, outputs: &outputs }];
        let blocks = source.blocks();
        let wroot = C61Commitment::new(vec![[65; 32]]);
        let aroot = C61Commitment::new(vec![[66; 32]]);
        let gamma = gamma(&matrix_config(32).unwrap());
        let profile = source.rms.bytes.profile(&gamma);
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let context = P0Statement {
            weights: &wroot,
            auxiliary: &aroot,
            weight_gamma: &gamma,
            auxiliary_gamma: &profile,
            auxiliary_layout: &source.rms.bytes.scalar,
            quantization: [67; 32],
            attempt,
            tokens: &[0, 1, 2, 3],
        };
        let count = lookup::Statement {
            root: &aroot,
            profile: &profile,
            view: source.view,
            attempt,
            blocks: &blocks,
            tables: &tables,
        }
        .required()
        .unwrap();
        assert_eq!(count, 669);
        let pairs = source.gate_rne_pairs(&[2]).unwrap();
        let count = count + source.rms.bytes.table_rne_required(plan, &pairs).unwrap();
        assert_eq!(count, 1158);
        let delta = signed(37);
        let mut rng = MatrixRng::from_seed([151; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let g = &source.gelu[0];
        let inputs = [-1i64, 1, 0, 2];
        let read = |id: usize, row: usize, col: usize, b: usize| {
            let (word, width) = if id == g.histogram {
                assert_eq!(row, 0);
                (if (32766..=32769).contains(&col) { 4i64 } else { 0 }, 4)
            } else {
                assert!(row < 4 && col < 4);
                if id == g.raw_gate {
                    (4 * inputs[col], 6)
                } else if id == g.input {
                    (inputs[col], 2)
                } else {
                    assert_eq!(id, g.output);
                    (inputs[col].max(0), 2)
                }
            };
            (((word + (1i64 << (8 * width - 1))) as u64) >> (8 * b)) as u8
        };
        let start =
            || Fs::new(b"canonical full-table GELU and gate RNE; pending source closures", 100_000);
        let mut fs = start();
        let mut prows = rows.into_iter();
        let (lookup, p) =
            source.prove_lookup(&context, &tables, read, &mut fs, &mut prows).unwrap();
        let (quantize, qp) = source
            .rms
            .bytes
            .prove_table_rne(plan, &context, &pairs, read, &mut fs, &mut prows)
            .unwrap();
        assert!(prows.next().is_none());
        let mut expected = [Fp3::ZERO; 3];
        for (i, w) in eq(&p.point).into_iter().enumerate() {
            match source.cell(i).unwrap() {
                Some(Cell::Query { column, .. }) => {
                    expected[0] += w * signed(inputs[column]);
                    expected[1] += w * signed(inputs[column].max(0));
                }
                Some(Cell::Histogram { entry, .. }) if (32766..=32769).contains(&entry) => {
                    expected[2] += w * signed(4)
                }
                _ => {}
            }
        }
        assert_eq!(p.originals.map(|a| a.x), expected);
        let mut fs = start();
        let mut vrows = keys.into_iter();
        let v =
            source.verify_lookup(&context, &tables, &lookup, delta, &mut fs, &mut vrows).unwrap();
        let qv = source
            .rms
            .bytes
            .verify_table_rne(plan, &context, &pairs, &quantize, delta, &mut fs, &mut vrows)
            .unwrap();
        assert!(vrows.next().is_none());
        for (a, k) in p.originals.into_iter().zip(v.originals) {
            assert_eq!(a.m + delta * a.x, k.k);
        }
        assert_eq!(qp[0].output.m + delta * qp[0].output.x, qv[0].output.k);
        assert_eq!(qp[0].raw.m + delta * qp[0].raw.x, qv[0].raw.k);
        assert_eq!(source.forms(&v.point).unwrap().0.len(), 3);
        assert_eq!(source.rms.bytes.table_rne_forms(plan, &pairs, &qv).unwrap().0.len(), 2);
        // Placeholder roots above grant NO PCS acceptance. The 600-row
        // lookup and 1,356-row P0/probe checks separately close actual PCS.
    }

    fn value(source: usize, row: usize, column: usize) -> i64 {
        17 * (source as i64 + 1) + 3 * row as i64 - (column % 17) as i64
    }

    #[test]
    fn c71_b12_gemma_gelu_sources_preserve_rms_and_original_query_histogram_byte_forms() {
        let mut plan = rms::tests::toy_plan(4, 2);
        let mut gate = plan.cohorts[1].clone();
        gate.layer = Some(0);
        gate.operation = "gate_proj".into();
        gate.producer = (None, "q_norm".into());
        plan.cohorts.push(gate);
        let before = plan.rms_sources().unwrap();
        let source = plan.gelu_sources().unwrap();
        canonical_lookup_and_gate_rne(&source, &plan);
        assert_eq!(source.queries, 16);
        assert_eq!(source.cells, 16 + 65535);
        assert_ne!(source.rms.view, before.view);
        for (old, new) in before.norms.iter().zip(&source.rms.norms) {
            assert_eq!(
                [old.input, old.product, old.statistic, old.output],
                [new.input, new.product, new.statistic, new.output]
            );
        }
        let mut packed = Vec::new();
        for (i, s) in source.rms.bytes.scalar.layout.sources.iter().enumerate() {
            let width = if let Some(c) = plan.cohorts.get(i) {
                match c.kind {
                    Kind::Matrix => 6,
                    Kind::Norm => 4,
                    Kind::Lookup => 2,
                }
            } else if s.name.starts_with("S/") {
                6
            } else if s.name.starts_with("M/GELU/") {
                4
            } else {
                2
            };
            for row in 0..s.rows {
                for col in 0..s.cols {
                    packed.extend_from_slice(&value(i, row, col).to_le_bytes()[..width]);
                }
            }
        }
        let mut actual = vec![0u8; source.rms.bytes.live.next_power_of_two()];
        for (i, b) in actual.iter_mut().enumerate().take(source.rms.bytes.live) {
            let (address, bias) = source.rms.bytes.virtual_to_packed(i).unwrap().unwrap();
            *b = packed[address] ^ bias;
        }
        let p: Vec<_> = (0..bits(source.cells)).map(|i| signed((i + 3) as i64)).collect();
        let (forms, shifts) = source.forms(&p).unwrap();
        let mut expected = [Fp3::ZERO; 3];
        for (i, w) in eq(&p).into_iter().enumerate() {
            match source.cell(i).unwrap() {
                Some(Cell::Query { gelu, row, column }) => {
                    let g = &source.gelu[gelu];
                    expected[0] += w * signed(value(g.input, row, column));
                    expected[1] += w * signed(value(g.output, row, column));
                }
                Some(Cell::Histogram { gelu, entry }) => {
                    expected[2] += w * signed(value(source.gelu[gelu].histogram, 0, entry));
                }
                None => {}
            }
        }
        for i in 0..3 {
            let found = forms[i].iter().fold(Fp3::ZERO, |sum, c| {
                sum + c.coefficient
                    * eq(&c.point).into_iter().enumerate().fold(Fp3::ZERO, |v, (j, w)| {
                        v + w * signed(i64::from(actual[c.offset + j]))
                    })
            });
            assert_eq!(found - shifts[i], expected[i]);
        }
        assert!(source.forms(&[]).is_err());
        assert!(source.cell(source.cells.next_power_of_two()).is_err());
        let original_name = before.bytes.scalar.layout.sources[0].name.clone();
        for extra in [
            (original_name, 1, 1, 2),
            ("invalid/shape".into(), 0, 1, 2),
            ("invalid/width".into(), 1, 1, 3),
        ] {
            assert!(plan.rms_sources().unwrap().append(vec![extra]).is_err());
        }

        let plan = super::super::compile().unwrap();
        let source = plan.gelu_sources().unwrap();
        assert_eq!(source.gelu.len(), 60);
        assert_eq!(source.queries, 193536000);
        assert_eq!(source.cells, 197468100);
        assert_eq!(source.rms.bytes.scalar.layout.sources.len(), 2326);
        assert_eq!(source.rms.bytes.live, 7881092238);
        assert_eq!(bits(source.rms.bytes.live), 33);
        let blocks = source.blocks();
        assert_eq!(blocks.len(), 1680);
        assert_eq!(blocks.iter().filter(|b| matches!(b, Block::Query { .. })).count(), 720);
        let mut offset = 0;
        for block in &blocks {
            let len = match *block {
                Block::Query { profile, len } => {
                    for i in [offset, offset + len - 1] {
                        let Some(Cell::Query { gelu, .. }) = source.cell(i).unwrap() else {
                            panic!("query block mapped to histogram")
                        };
                        assert_eq!(source.gelu[gelu].layer, profile);
                    }
                    len
                }
                Block::Table { index, first, len } => {
                    for (i, expected) in [(offset, first), (offset + len - 1, first + len - 1)] {
                        let Some(Cell::Histogram { gelu, entry }) = source.cell(i).unwrap() else {
                            panic!("table block mapped to query")
                        };
                        assert_eq!((gelu, entry), (index, expected));
                    }
                    len
                }
            };
            offset += len;
        }
        assert_eq!(offset, source.cells);
        let p: Vec<_> = (0..28).map(|i| signed((i + 5) as i64)).collect();
        let (forms, _) = source.forms(&p).unwrap();
        assert_eq!(forms.each_ref().map(Vec::len), [720, 720, 960]);
        let pairs = source.gate_rne_pairs(&vec![0; 60]).unwrap();
        assert!(source.gate_rne_pairs(&[]).is_err());
        let pending: Vec<_> = (0..60)
            .map(|i| bytes::quantize::Opening {
                output_point: (0..23).map(|j| signed((j + 3) as i64)).collect(),
                output: 2 * i,
                raw_point: (0..26).map(|j| signed((j + 7) as i64)).collect(),
                raw: 2 * i + 1,
            })
            .collect();
        let (forms, _, originals) =
            source.rms.bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
        assert_eq!(forms.len(), 120);
        assert_eq!(forms.iter().step_by(2).map(Vec::len).sum::<usize>(), 720);
        assert_eq!(forms.iter().skip(1).step_by(2).map(Vec::len).sum::<usize>(), 1440);
        assert_eq!(originals, (0..120).collect::<Vec<_>>());
        assert!(source.rms.bytes.table_rne_required(&plan, &pairs).is_err()); // D23 remains analytic
        for g in &source.gelu {
            assert_eq!(plan.cohorts[g.raw_gate].operation, "gate_proj");
            assert_eq!(plan.cohorts[g.raw_gate].layer, Some(u64::from(g.layer)));
            let s = &source.rms.bytes.scalar.layout.sources[g.output];
            assert_eq!(s.name, format!("X/{}/gelu_tanh", g.layer));
            assert_eq!([s.rows, s.cols], [150, 21504]);
        }
    }
}

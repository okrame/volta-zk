//! Canonical GELU inputs/outputs/histograms in the SAME P0/RMS byte source.
//! Public metadata only: actual tables, RNE proofs and the driver are separate.

use super::rms::prefix as point;
use super::*;
use crate::c71_matrix::lookup::Block;

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
        for g in &source.gelu {
            assert_eq!(plan.cohorts[g.raw_gate].operation, "gate_proj");
            assert_eq!(plan.cohorts[g.raw_gate].layer, Some(u64::from(g.layer)));
            let s = &source.rms.bytes.scalar.layout.sources[g.output];
            assert_eq!(s.name, format!("X/{}/gelu_tanh", g.layer));
            assert_eq!([s.rows, s.cols], [150, 21504]);
        }
    }
}

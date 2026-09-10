//! Canonical fresh-run RoPE views: the exact RMS outputs, joint raw linear
//! relation and whole-table output RNE all close in the SAME byte source.

use super::caller::P0Statement;
use super::rms::prefix as point;
use super::*;
use crate::c71_matrix::{rope as kernel, Fs};

pub(in crate::c71_matrix) struct Rotation {
    pub norm: usize,
    pub raw: usize,
    pub output: usize,
    pub layer: u8,
    pub query: bool,
    pub rows: usize,
    pub heads: usize,
    pub width: usize,
    pub family: usize,
}

pub(in crate::c71_matrix) struct Sources {
    pub gate_up: gate_up::Sources,
    pub rotations: Vec<Rotation>,
    pub cells: usize,
    pub view: [u8; 32],
    pub blocks: Vec<kernel::Block>,
    tiles: Vec<Tile>,
}

impl Plan {
    pub fn rope_sources(&self) -> Result<Sources, String> {
        let gate_up = self.gate_up_sources()?;
        let mut rotations = Vec::new();
        let mut identities = std::collections::BTreeSet::new();
        for (i, n) in gate_up.gelu.rms.norms.iter().enumerate() {
            if !matches!(n.operation.as_str(), "q_norm" | "k_norm") {
                continue;
            }
            let layer = n.layer.ok_or("RoPE normalization layer missing")?;
            let query = n.operation == "q_norm";
            let family = usize::from(layer % 6 == 5);
            let width = if family == 0 { 256 } else { 512 };
            let heads = if query {
                32
            } else if family == 0 {
                16
            } else {
                4
            };
            if layer >= 60
                || !identities.insert((layer, query))
                || n.cohort.is_none()
                || n.heads != heads
                || n.columns != width
                || n.rows != 150 * heads
            {
                return Err(
                    "RoPE source differs from the pinned fresh 150-token Q/K geometry".into()
                );
            }
            rotations.push(Rotation {
                norm: i,
                raw: 0,
                output: 0,
                layer: layer as u8,
                query,
                rows: 150,
                heads,
                width,
                family,
            });
        }
        if rotations.len() != 120 {
            return Err("RoPE needs all 120 Q/K normalization outputs".into());
        }
        let base = gate_up.gelu.rms.bytes.scalar.layout.sources.len();
        let mut extra = Vec::new();
        for (i, r) in rotations.iter_mut().enumerate() {
            r.raw = base + i;
            r.output = base + 120 + i;
            extra.push((
                format!("R/{}/{}_rope", r.layer, if r.query { "q" } else { "k" }),
                r.rows,
                r.heads * r.width,
                6,
            ));
        }
        for r in &rotations {
            extra.push((
                format!("X/{}/{}_rope", r.layer, if r.query { "q" } else { "k" }),
                r.rows,
                r.heads * r.width,
                2,
            ));
        }
        let gate_up = gate_up.append(extra)?;
        let words: Vec<_> = rotations
            .iter()
            .map(|r| Source {
                name: format!("RoPE/{}", r.raw),
                rows: r.rows,
                cols: r.heads * r.width,
                packed_offset: 0,
            })
            .collect();
        let (tiles, cells) = tiles(&words);
        let mut blocks = Vec::new();
        for t in &tiles {
            let r = &rotations[t.tensor];
            if t.col != 0 || t.cols != r.heads * r.width {
                return Err("RoPE tile must preserve the full head axes".into());
            }
            blocks.push(kernel::Block {
                rows: t.rows,
                heads: r.heads,
                width: r.width,
                position: t.row,
                family: r.family,
            });
        }
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-RoPE-source-v1;fresh-O0;150-tokens;Q30;original-RMS-Y;dyadic-MSB\0");
        digest.update(&gate_up.view);
        for r in &rotations {
            let n = &gate_up.gelu.rms.norms[r.norm];
            for v in [
                r.norm,
                n.output,
                r.raw,
                r.output,
                r.layer as usize,
                usize::from(r.query),
                r.rows,
                r.heads,
                r.width,
                r.family,
            ] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        for t in &tiles {
            for v in [t.tensor, t.row, t.col, t.rows, t.cols, t.offset] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        Ok(Sources {
            gate_up,
            rotations,
            cells,
            view: *digest.finalize().as_bytes(),
            blocks,
            tiles,
        })
    }
}

impl Sources {
    pub fn cell(&self, index: usize) -> Result<Option<(usize, usize, usize)>, String> {
        if index >= self.cells.next_power_of_two() {
            return Err("RoPE cell exceeds padded source domain".into());
        }
        if index >= self.cells {
            return Ok(None);
        }
        let t = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let local = index - t.offset;
        Ok(Some((t.tensor, t.row + local / t.cols, t.col + local % t.cols)))
    }

    /// The global raw and RMS-output MACs keep the SAME word-to-byte maps.
    pub fn forms(&self, raw: &[Fp3], input: &[Fp3]) -> Result<([Vec<Cube>; 2], [Fp3; 2]), String> {
        let c = bits(self.cells);
        if raw.len() != c || input.len() != c {
            return Err("RoPE original points differ".into());
        }
        let mut forms: [Vec<Cube>; 2] = std::array::from_fn(|_| Vec::new());
        let mut shifts = [Fp3::ZERO; 2];
        for t in &self.tiles {
            let r = &self.rotations[t.tensor];
            let n = &self.gate_up.gelu.rms.norms[r.norm];
            let low = bits(t.rows) + bits(t.cols);
            for (i, id, q) in [(0, r.raw, raw), (1, n.output, input)] {
                let coefficient = eq_index(&q[..c - low], t.offset / (t.rows * t.cols));
                let rp = point(t.row, t.rows, r.rows, &q[c - low..c - bits(t.cols)]);
                let cp = &q[c - bits(t.cols)..];
                let (form, shift) =
                    self.gate_up.gelu.rms.bytes.word_form(id, &rp, cp, coefficient)?;
                forms[i].extend(form);
                shifts[i] += shift;
            }
        }
        Ok((forms, shifts))
    }

    pub fn rne_pairs(&self, shifts: &[i32]) -> Result<Vec<bytes::quantize::Pair>, String> {
        if shifts.len() != self.rotations.len() {
            return Err("RoPE public shift profile differs".into());
        }
        Ok(self
            .rotations
            .iter()
            .zip(shifts)
            .map(|(r, &shift)| bytes::quantize::Pair { raw: r.raw, output: r.output, shift })
            .collect())
    }

    pub fn statement<'a>(
        &'a self,
        s: &'a P0Statement<'_>,
        tables: &'a [kernel::Table<'a>],
        fs: &mut Fs,
    ) -> Result<kernel::Statement<'a>, String> {
        if tables.len() != 2
            || tables.iter().enumerate().any(|(f, t)| {
                t.position != 0
                    || t.rows.len() != 150
                    || t.rows.iter().any(|r| r.len() != if f == 0 { 128 } else { 64 })
            })
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.tokens.len() != 150
            || s.auxiliary_layout.layout.layout_digest
                != self.gate_up.gelu.rms.bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != self.gate_up.gelu.rms.bytes.scalar.weight_layout
        {
            return Err("RoPE certified table window or fixed source context differs".into());
        }
        let mut bytes = b"C71-canonical-RoPE-B12-v1;fresh-O0;Q30;original-RMS-Y\0".to_vec();
        bytes.extend(s.weights.roots()[0]);
        bytes.extend(s.auxiliary.roots()[0]);
        for g in [s.weight_gamma, s.auxiliary_gamma] {
            bytes.extend((g.len() as u64).to_le_bytes());
            bytes.extend(g);
        }
        bytes.extend(s.quantization);
        bytes.extend(s.attempt.encode());
        bytes.extend(self.view);
        fs.set_phase(0x1120);
        fs.record(0xe3, &bytes);
        Ok(kernel::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.view,
            attempt: s.attempt,
            blocks: &self.blocks,
            tables,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{signed, AttemptContext, C61Commitment};

    #[test]
    fn c71_b12_gemma_rope_sources_route_all_original_rms_outputs_and_joint_rne_forms() {
        let plan = compile().unwrap();
        let before = plan.gate_up_sources().unwrap();
        let source = plan.rope_sources().unwrap();
        assert_eq!(source.rotations.len(), 120);
        assert_eq!(source.cells, 119808000);
        assert_eq!(source.blocks.len(), 480);
        let bytes = &source.gate_up.gelu.rms.bytes;
        assert_eq!(bytes.live, 10387844238);
        assert_eq!(bits(bytes.live), 34);
        assert_eq!(bytes.scalar.layout.sources.len(), 2686);
        assert_ne!(source.gate_up.view, before.view);
        assert_ne!(source.gate_up.gelu.view, before.gelu.view);
        assert_ne!(source.gate_up.gelu.rms.view, before.gelu.rms.view);
        for (old, new) in before.gelu.rms.norms.iter().zip(&source.gate_up.gelu.rms.norms) {
            assert_eq!(
                [old.input, old.product, old.statistic, old.output],
                [new.input, new.product, new.statistic, new.output]
            );
        }
        for (old, new) in before.products.iter().zip(&source.gate_up.products) {
            assert_eq!(
                [old.up, old.raw, old.output, old.down],
                [new.up, new.raw, new.output, new.down]
            );
        }
        let q: Vec<_> = (0..27).map(|i| signed(i + 3)).collect();
        let (forms, _) = source.forms(&q, &q).unwrap();
        assert_eq!(forms.each_ref().map(Vec::len), [960, 480]);
        let mut offset = 0;
        for (b, t) in source.blocks.iter().zip(&source.tiles) {
            let r = &source.rotations[t.tensor];
            assert_eq!(
                (b.family, b.position, b.heads, b.width),
                (r.family, t.row, r.heads, r.width)
            );
            assert_eq!(source.cell(offset).unwrap(), Some((t.tensor, t.row, 0)));
            offset += b.rows * b.heads * b.width;
            assert_eq!(
                source.cell(offset - 1).unwrap(),
                Some((t.tensor, t.row + t.rows - 1, t.cols - 1))
            );
        }
        assert_eq!(offset, source.cells);
        assert_eq!(source.cell(source.cells).unwrap(), None);
        let pairs = source.rne_pairs(&vec![30; 120]).unwrap();
        let mut csum = 0;
        let pending: Vec<_> = source
            .rotations
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let n = &source.gate_up.gelu.rms.norms[r.norm];
                assert_eq!(n.layer, Some(r.layer as u64));
                assert_eq!(n.operation, if r.query { "q_norm" } else { "k_norm" });
                assert_eq!(n.rows / r.heads, 150);
                assert_eq!(
                    bytes.scalar.layout.sources[n.output].name,
                    format!("X/{}/{}", r.layer, n.operation)
                );
                assert_eq!((pairs[i].raw, pairs[i].output), (r.raw, r.output));
                assert!(r.raw >= plan.cohorts.len()); // non-matrix raw source
                let c = bits(r.rows) + bits(r.heads * r.width);
                csum += c;
                bytes::quantize::Opening {
                    output_point: (0..c).map(|j| signed(j as i64 + 3)).collect(),
                    output: 2 * i,
                    raw_point: (0..c + 3).map(|j| signed(j as i64 + 7)).collect(),
                    raw: 2 * i + 1,
                }
            })
            .collect();
        assert_eq!(csum, 2460);
        let (forms, _, originals) = bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
        assert_eq!(forms.len(), 240);
        assert_eq!(forms.iter().step_by(2).map(Vec::len).sum::<usize>(), 480);
        assert_eq!(forms.iter().skip(1).step_by(2).map(Vec::len).sum::<usize>(), 960);
        assert_eq!(originals, (0..240).collect::<Vec<_>>());
        assert!(bytes.table_rne_required(&plan, &pairs).is_err());
        assert!(source.rne_pairs(&[]).is_err());
        let root = C61Commitment::new(vec![[1; 32]]);
        let profile = [2; 32];
        let tokens = [0; 150];
        let context = P0Statement {
            weights: &root,
            auxiliary: &root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &bytes.scalar,
            quantization: [3; 32],
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [3; 32],
            },
            tokens: &tokens,
        };
        // Only public window shape/context is checked here; these synthetic
        // table bodies are NOT certified Q30 and grant no execution credit.
        let local = vec![vec![[1 << 30, 0]; 128]; 150];
        let global = vec![vec![[1 << 30, 0]; 64]; 150];
        let tables = [
            kernel::Table { position: 0, rows: &local },
            kernel::Table { position: 0, rows: &global },
        ];
        let mut fs = Fs::new(b"canonical RoPE metadata, no full-domain execution", 10000);
        let statement = source.statement(&context, &tables, &mut fs).unwrap();
        assert!(statement.required().is_err()); // D27 is not native D15
        assert_eq!(fs.requests(), 0);
        assert!(source.statement(&context, &tables[..1], &mut fs).is_err());
        assert!(source
            .statement(&P0Statement { tokens: &tokens[..149], ..context }, &tables, &mut fs)
            .is_err());
        // Previous forms still compile against the extended byte offsets.
        let p: Vec<_> = (0..28).map(|i| signed(i + 5)).collect();
        assert_eq!(
            source.gate_up.forms(&p, &p).unwrap().0.each_ref().map(Vec::len),
            [1440, 720, 720]
        );
        assert_eq!(
            source.gate_up.gelu.forms(&p).unwrap().0.each_ref().map(Vec::len),
            [720, 720, 960]
        );
    }
}

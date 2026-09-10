//! Original lm_head raw -> RNE -> certified public softcap -> public argmax.
//! Every source and slack belongs to the same A used by the other producers.

use super::caller::P0Statement;
use super::rms::prefix;
use super::*;
use crate::c71_matrix::{lookup, Auth, Fs, Key};

pub(in crate::c71_matrix) struct Output {
    pub raw: usize,
    pub input: usize,
    pub output: usize,
    pub histogram: usize,
    pub slack: usize,
    pub lower: i16,
    pub token_offset: usize,
}

impl Plan {
    pub fn output_sources_at(&self, old: usize) -> Result<(residual::Sources, Output), String> {
        let mut sources = self.residual_sources_at(old)?;
        let raw = self.cohorts.len() - 1;
        let head = &self.cohorts[raw];
        if head.kind != Kind::Matrix
            || head.operation != "lm_head"
            || head.layer.is_some()
            || [head.rows, head.columns] != [50, 262144]
            || head.tensor != self.cohorts[0].tensor
        {
            return Err("output original tied lm_head shape differs".into());
        }
        let base = sources.attention.rope.gate_up.gelu.rms.bytes.scalar.layout.sources.len();
        let output = Output {
            raw,
            input: base,
            output: base + 1,
            histogram: base + 2,
            slack: base + 3,
            lower: -32767,
            token_offset: 100,
        };
        sources.attention = sources.attention.append(vec![
            ("X/global/lm_head".into(), 50, 262144, 2),
            ("X/global/final_tanh_softcap".into(), 50, 262144, 2),
            ("M/global/final_tanh_softcap".into(), 1, 65535, 4),
            ("U/global/argmax_slack".into(), 50, 262144, 2),
        ])?;
        Ok((sources, output))
    }
}

impl Output {
    fn layout(&self, bytes: &bytes::Bytes) -> Result<(Vec<Tile>, usize), String> {
        let x = bytes.scalar.layout.sources.get(self.input).ok_or("softcap input missing")?;
        let y = bytes.scalar.layout.sources.get(self.output).ok_or("softcap output missing")?;
        let m =
            bytes.scalar.layout.sources.get(self.histogram).ok_or("softcap histogram missing")?;
        if [x.rows, x.cols] != [y.rows, y.cols]
            || m.rows != 1
            || m.cols == 0
            || m.cols > 65535
            || bytes.widths[self.input] != 2
            || bytes.widths[self.output] != 2
            || bytes.widths[self.histogram] != 4
            || self.input == self.output
        {
            return Err("softcap source axes or codecs differ".into());
        }
        Ok(tiles(&[x.clone(), m.clone()]))
    }

    fn bind(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        table: &lookup::Table<'_>,
        fs: &mut Fs,
    ) -> Result<[u8; 32], String> {
        self.layout(bytes)?;
        if table.profile != 0
            || !matches!(table.outputs, lookup::Outputs::I16(_))
            || table.lower != self.lower
            || table.outputs.len() != bytes.scalar.layout.sources[self.histogram].cols
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.auxiliary_layout.layout.layout_digest != bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != bytes.scalar.weight_layout
        {
            return Err("softcap certified public table or fixed source context differs".into());
        }
        // Table bodies are the verifier's CERTIFIED profile, not a prover
        // supplied function certified merely by its digest or shape.
        let mut frame =
            b"C71-final-softcap-B12-v1;original-head-X-Y-M;certified-public-table\0".to_vec();
        frame.extend(s.weights.roots()[0]);
        frame.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            frame.extend((gamma.len() as u64).to_le_bytes());
            frame.extend(gamma);
        }
        frame.extend(bytes.layout_digest);
        frame.extend(s.quantization);
        frame.extend(s.attempt.encode());
        for n in [self.raw, self.input, self.output, self.histogram, self.slack, self.token_offset]
        {
            frame.extend((n as u64).to_le_bytes());
        }
        frame.extend(self.lower.to_le_bytes());
        let view = *blake3::hash(&frame).as_bytes();
        fs.set_phase(0x1600);
        fs.record(0xfe, &frame);
        Ok(view)
    }

    pub fn blocks(&self, bytes: &bytes::Bytes) -> Result<Vec<lookup::Block>, String> {
        Ok(self
            .layout(bytes)?
            .0
            .iter()
            .map(|t| {
                if t.tensor == 0 {
                    lookup::Block::Query { profile: 0, len: t.rows * t.cols }
                } else {
                    lookup::Block::Table { index: 0, first: t.col, len: t.cols }
                }
            })
            .collect())
    }

    pub fn prove_lookup(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        table: lookup::Table<'_>,
        read: impl Fn(usize, usize, usize, usize) -> u8,
        fs: &mut Fs,
        rows: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(lookup::Proof, lookup::Pending<Auth>), String> {
        let view = self.bind(bytes, s, &table, fs)?;
        let (tiles, _) = self.layout(bytes)?;
        let blocks = self.blocks(bytes)?;
        lookup::prove(
            &lookup::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view,
                attempt: s.attempt,
                blocks: &blocks,
                tables: &[table],
            },
            |i| {
                let t = &tiles[tiles.partition_point(|t| t.offset <= i) - 1];
                assert_eq!(t.tensor, 0);
                let (r, c) = (t.row + (i - t.offset) / t.cols, t.col + (i - t.offset) % t.cols);
                let word = |id| {
                    (i32::from(u16::from_le_bytes([read(id, r, c, 0), read(id, r, c, 1)])) - 32768)
                        as i16
                };
                (word(self.input), word(self.output))
            },
            |j| {
                let b = u32::from_le_bytes(std::array::from_fn(|k| read(self.histogram, 0, j, k)));
                (i64::from(b) - (1 << 31)) as i32
            },
            fs,
            rows,
        )
    }

    pub fn verify_lookup(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        table: lookup::Table<'_>,
        proof: &lookup::Proof,
        delta: Fp3,
        fs: &mut Fs,
        rows: &mut std::vec::IntoIter<Key>,
    ) -> Result<lookup::Pending<Key>, String> {
        let view = self.bind(bytes, s, &table, fs)?;
        let blocks = self.blocks(bytes)?;
        lookup::verify(
            &lookup::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view,
                attempt: s.attempt,
                blocks: &blocks,
                tables: &[table],
            },
            proof,
            delta,
            fs,
            rows,
        )
    }

    pub fn rne_pair(&self, shift: i32) -> bytes::quantize::Pair {
        bytes::quantize::Pair { raw: self.raw, output: self.input, shift }
    }

    pub fn forms(
        &self,
        bytes: &bytes::Bytes,
        point: &[Fp3],
    ) -> Result<([Vec<Cube>; 3], [Fp3; 3]), String> {
        let (tiles, cells) = self.layout(bytes)?;
        let d = bits(cells);
        if point.len() != d {
            return Err("softcap original lookup point differs".into());
        }
        let mut forms: [Vec<Cube>; 3] = std::array::from_fn(|_| Vec::new());
        let mut shifts = [Fp3::ZERO; 3];
        for t in tiles {
            let local = bits(t.rows) + bits(t.cols);
            let coefficient = eq_index(&point[..d - local], t.offset / (t.rows * t.cols));
            for (lane, id) in [(0, self.input), (1, self.output), (2, self.histogram)] {
                if (lane == 2) != (t.tensor == 1) {
                    continue;
                }
                let source = &bytes.scalar.layout.sources[id];
                let row = prefix(t.row, t.rows, source.rows, &point[d - local..d - bits(t.cols)]);
                let col = prefix(t.col, t.cols, source.cols, &point[d - bits(t.cols)..]);
                let (f, b) = bytes.word_form(id, &row, &col, coefficient)?;
                forms[lane].extend(f);
                shifts[lane] += b;
            }
        }
        Ok((forms, shifts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{
        from_p3, gamma, linear, matrix_config, range, signed, AttemptContext, C61Commitment,
        MatrixRng, Model, E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_output_head_rne_softcap_and_public_argmax_share_original_a() {
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let base = bytes.scalar.layout.sources.len();
        let route = Output {
            raw: base,
            input: base + 1,
            output: base + 2,
            histogram: base + 3,
            slack: base + 4,
            lower: -3,
            token_offset: 1,
        };
        let bytes = bytes
            .append(vec![
                ("output/raw".into(), 3, 4, 6),
                ("output/X".into(), 3, 4, 2),
                ("output/Y".into(), 3, 4, 2),
                ("output/M".into(), 1, 7, 4),
                ("output/slack".into(), 3, 4, 2),
            ])
            .unwrap();
        assert!(bytes.live <= 1024);
        let pairs = [route.rne_pair(2)];
        let count = bytes.table_rne_required(&plan, &pairs).unwrap()
            + lookup::required(bits(route.layout(&bytes).unwrap().1))
            + range::required(10, range::Alphabet::Byte)
            + 32;
        assert_eq!(count, 1112);
        let profile = gamma(&matrix_config(32).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(53);
        // Certified subset of C71-SOFTCAP-RNE-v1 at (10,2), inputs -3..3.
        // Python checks this exact table; the canonical table has 65535 rows.
        let table = || lookup::Table {
            profile: 0,
            lower: -3,
            outputs: lookup::Outputs::I16(&[-7, -7, -7, 0, 7, 7, 7]),
        };
        for fault in 0..5 {
            let x = if fault == 4 {
                [[0i64; 4]; 3]
            } else {
                [[-3i64, 3, -1, 0], [1, 2, -1, 0], [0, -1, 2, 3]]
            };
            let mut tokens = [3u32, 1, 0, 2];
            if fault >= 3 {
                tokens[2] = 1;
            }
            let y = |r: usize, c: usize| {
                let value = 7 * x[r][c].signum();
                if fault == 2 && r == 0 && c == 1 {
                    value - 1
                } else {
                    value
                }
            };
            let value = |id, r: usize, c: usize| {
                if id == route.raw {
                    return 4 * x[r][c] + if fault == 1 && r == 0 && c == 0 { 4 } else { 0 };
                }
                if id == route.input {
                    return x[r][c];
                }
                if id == route.output {
                    return y(r, c);
                }
                if id == route.histogram {
                    return x.iter().flatten().filter(|&&v| v == c as i64 - 3).count() as i64;
                }
                if id == route.slack {
                    if fault == 4 {
                        return -32768;
                    } // unsigned zero, fake decisions need DV keys
                    return (y(r, tokens[r + 1] as usize)
                        - y(r, c)
                        - i64::from(c < tokens[r + 1] as usize))
                    .rem_euclid(1 << 16)
                        - 32768;
                }
                0
            };
            let read = |id: usize, r: usize, c: usize, b: usize| {
                ((value(id, r, c) as u64 >> (8 * b)) as u8)
                    ^ if b + 1 == bytes.widths[id] { 128 } else { 0 }
            };
            let mut packed = Vec::new();
            for (id, s) in bytes.scalar.layout.sources.iter().enumerate() {
                for r in 0..s.rows {
                    for c in 0..s.cols {
                        packed
                            .extend_from_slice(&value(id, r, c).to_le_bytes()[..bytes.widths[id]]);
                    }
                }
            }
            assert_eq!(packed.len(), bytes.live);
            let model = Model::new(
                32,
                (0..1024)
                    .map(|i| {
                        bytes
                            .virtual_to_packed(i)
                            .unwrap()
                            .map_or(0, |(a, x)| i16::from(packed[a] ^ x))
                    })
                    .collect(),
            )
            .unwrap();
            let context = P0Statement {
                weights: &model.root,
                auxiliary: &model.root,
                weight_gamma: &profile,
                auxiliary_gamma: &profile,
                auxiliary_layout: &bytes.scalar,
                quantization: [5; 32],
                attempt,
                tokens: &tokens,
            };
            let mut rng = MatrixRng::from_seed([132 + fault; 32]);
            // Ideal MAC fixture sampled conditional on the verifier's keys.
            // In the simulator case these keys, Delta and PUBLIC tokens are
            // the only inputs; every witness value above is a dummy zero.
            let keys: Vec<_> = (0..count).map(|_| Key::new(from_p3(rng.random::<E>()))).collect();
            let rows: Vec<_> = keys
                .iter()
                .map(|k| {
                    let x = from_p3(rng.random::<E>());
                    Auth::new(x, k.k - delta * x)
                })
                .collect();
            let start = || Fs::new(b"original head RNE softcap argmax one ranged source", 100000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (zero, bias) = bytes
                .argmax_zero_form(
                    &plan,
                    &context,
                    route.output,
                    route.slack,
                    route.token_offset,
                    &mut fs,
                )
                .unwrap();
            let (rne, rp) =
                bytes.prove_table_rne(&plan, &context, &pairs, read, &mut fs, &mut prows).unwrap();
            let (look, lp) =
                route.prove_lookup(&bytes, &context, table(), read, &mut fs, &mut prows).unwrap();
            let (range, forms, targets) = range::prove(
                &model,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(forms), Vec::from(targets));
            forms.push(zero);
            targets.push(if fault == 4 {
                // DV SIMULATOR ONLY: original public key is Delta*bias.
                // Dummy Y/slack give form value zero. Auth(0,Delta*bias)
                // has that SAME key. There is no new correction or changed
                // verifier target; a malicious prover does not know Delta.
                assert_ne!(bias, Fp3::ZERO);
                Auth::new(Fp3::ZERO, delta * bias)
            } else {
                Auth::new(bias, Fp3::ZERO)
            });
            let (f, b, t) = bytes.table_rne_forms(&plan, &pairs, &rp).unwrap();
            forms.extend(f);
            targets.extend(t.into_iter().zip(b).map(|(a, b)| Auth::new(a.x + b, a.m)));
            let (f, b) = route.forms(&bytes, &lp.point).unwrap();
            forms.extend(f);
            targets.extend(lp.originals.into_iter().zip(b).map(|(a, b)| Auth::new(a.x + b, a.m)));
            let (pcs, digest) = linear::prove(
                &model,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let (zero, bias) = bytes
                .argmax_zero_form(
                    &plan,
                    &context,
                    route.output,
                    route.slack,
                    route.token_offset,
                    &mut fs,
                )
                .unwrap();
            let rp =
                bytes.verify_table_rne(&plan, &context, &pairs, &rne, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert!(rp.is_err(), "wrong original raw passed head RNE");
                continue;
            }
            let rp = rp.unwrap();
            let lp =
                route.verify_lookup(&bytes, &context, table(), &look, delta, &mut fs, &mut vrows);
            if fault == 2 {
                assert!(lp.is_err(), "wrong softcap Y passed original lookup");
                continue;
            }
            let lp = lp.unwrap();
            let (forms, targets) = range::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &range,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(forms), Vec::from(targets));
            forms.push(zero);
            targets.push(Key::new(delta * bias));
            let (f, b, t) = bytes.table_rne_forms(&plan, &pairs, &rp).unwrap();
            forms.extend(f);
            targets.extend(t.into_iter().zip(b).map(|(k, b)| Key::new(k.k + delta * b)));
            let (f, b) = route.forms(&bytes, &lp.point).unwrap();
            forms.extend(f);
            targets.extend(lp.originals.into_iter().zip(b).map(|(k, b)| Key::new(k.k + delta * b)));
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 0 || fault == 4 {
                assert_eq!(result.unwrap(), digest);
            } else {
                assert!(result.is_err(), "wrong public tie decision passed same source PCS");
            }
            assert!(vrows.next().is_none());
        }
        // All full-size routes compile, preserving the original P0 raw ID.
        let plan = compile().unwrap();
        for old in [0, 150, 300] {
            let (sources, route) = plan.output_sources_at(old).unwrap();
            let bytes = &sources.attention.rope.gate_up.gelu.rms.bytes;
            assert_eq!(route.raw, 772);
            assert_eq!(route.token_offset, 100);
            assert_eq!(bytes.scalar.layout.sources.len(), 3171);
            assert_eq!(bytes.live, 12613738638 + 4915200 * old + 78905340);
            assert_eq!(bits(bytes.live), 34);
            let (tiles, cells) = route.layout(bytes).unwrap();
            assert_eq!((tiles.len(), cells), (19, 13172735));
            let point: Vec<_> = (0..24).map(|i| signed(i + 2)).collect();
            let (forms, _) = route.forms(bytes, &point).unwrap();
            assert_eq!(forms.each_ref().map(Vec::len), [3, 3, 16]);
            let tokens: Vec<_> = (0..150).map(|i| i * 1709 % 262144).collect();
            let root = C61Commitment::new(vec![[14; 32]]);
            let context = P0Statement {
                weights: &root,
                auxiliary: &root,
                weight_gamma: &profile,
                auxiliary_gamma: &profile,
                auxiliary_layout: &bytes.scalar,
                quantization: [5; 32],
                attempt,
                tokens: &tokens,
            };
            let mut fs = Fs::new(b"canonical output metadata only", 1000);
            let (forms, _) = bytes
                .argmax_zero_form(
                    &plan,
                    &context,
                    route.output,
                    route.slack,
                    route.token_offset,
                    &mut fs,
                )
                .unwrap();
            assert_eq!(forms.len(), 56);
            assert_eq!(fs.requests(), 24);
            assert!(bytes.table_rne_required(&plan, &[route.rne_pair(2)]).is_err());
        }
    }
}

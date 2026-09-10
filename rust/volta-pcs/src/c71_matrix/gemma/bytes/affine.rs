//! Public linear raw identities are ZERO targets in the existing source PCS.
//! The same biased bytes also supply the original RNE endpoints.

use super::*;
use crate::c71_matrix::gemma::{caller::P0Statement, rms::prefix};
use crate::c71_matrix::{signed, Fs};

pub(in crate::c71_matrix) struct Relation {
    pub raw: usize,
    pub inputs: [(usize, i64); 2], // R = a*X + b*Y; zero second coefficient for scale
}

impl Bytes {
    /// Both roles call the SAME public function, after fixing roots/profile.
    /// Return one form with PUBLIC target `bias`: Auth(bias,0), Key(delta*bias).
    /// No new private MAC, product, sumcheck or independently committed input.
    pub fn affine_zero_form(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        relations: &[Relation],
        fs: &mut Fs,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        if relations.is_empty()
            || relations.len() > 512
            || self.scalar.weight_layout != plan.layout_digest
            || s.auxiliary_layout.layout.layout_digest != self.scalar.layout.layout_digest
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
        {
            return Err("affine zero-form fixed source or profile differs".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let (mut words, mut cells, mut cubes) = (Vec::new(), 0usize, 0usize);
        for r in relations {
            let raw = self.scalar.layout.sources.get(r.raw).ok_or("affine raw source missing")?;
            if self.widths[r.raw] != 6 || !seen.insert(r.raw) {
                return Err("affine raw codec or identity differs".into());
            }
            let mut terms = 2; // biased i48 raw has 4+2 byte cubes
            for &(id, coefficient) in &r.inputs {
                let input = self.scalar.layout.sources.get(id).ok_or("affine input missing")?;
                if self.widths[id] != 2
                    || [input.rows, input.cols] != [raw.rows, raw.cols]
                    || coefficient.unsigned_abs() > 1 << 30
                {
                    return Err(
                        "affine input codec, shape or coefficient exceeds integer envelope".into(),
                    );
                }
                terms += usize::from(coefficient != 0);
            }
            cells = cells
                .checked_add(raw.rows.checked_mul(raw.cols).ok_or("affine shape overflow")?)
                .ok_or("affine cell count overflow")?;
            cubes += raw.rows.count_ones() as usize * raw.cols.count_ones() as usize * terms;
            words.push(raw.clone());
        }
        if cells == 0 || cells > 1 << 35 || cubes > crate::c71_matrix::linear::MAX_CUBES {
            return Err("affine zero-form public domain or cube cap exceeded".into());
        }
        let (tiles, cells) = tiles(&words);
        let c = bits(cells);
        let mut transcript =
            b"C71-affine-raw-zero-B12-v1;original-A-bytes;public-target;dyadic-MSB\0".to_vec();
        transcript.extend(s.weights.roots()[0]);
        transcript.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            transcript.extend((gamma.len() as u64).to_le_bytes());
            transcript.extend(gamma);
        }
        transcript.extend(plan.layout_digest);
        transcript.extend(self.layout_digest);
        transcript.extend(s.quantization);
        transcript.extend(s.attempt.encode());
        transcript.extend((relations.len() as u64).to_le_bytes());
        for r in relations {
            transcript.extend((r.raw as u64).to_le_bytes());
            for &(id, coefficient) in &r.inputs {
                transcript.extend((id as u64).to_le_bytes());
                transcript.extend(coefficient.to_le_bytes());
            }
        }
        fs.set_phase(0x1300);
        fs.record(0xfa, &transcript);
        let point: Vec<_> = (0..c).map(|_| fs.fp3()).collect();
        let (mut form, mut bias) = (Vec::new(), Fp3::ZERO);
        for t in &tiles {
            let r = &relations[t.tensor];
            let raw = &words[t.tensor];
            let low = bits(t.rows) + bits(t.cols);
            let weight = eq_index(&point[..c - low], t.offset / (t.rows * t.cols));
            let row = prefix(t.row, t.rows, raw.rows, &point[c - low..c - bits(t.cols)]);
            let col = prefix(t.col, t.cols, raw.cols, &point[c - bits(t.cols)..]);
            for (id, coefficient) in
                [(r.raw, 1), (r.inputs[0].0, -r.inputs[0].1), (r.inputs[1].0, -r.inputs[1].1)]
            {
                if coefficient == 0 {
                    continue;
                }
                let (f, b) = self.word_form(id, &row, &col, weight * signed(coefficient))?;
                form.extend(f);
                bias += b;
            }
        }
        Ok((form, bias))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{
        from_p3, gamma, linear, matrix_config, range, AttemptContext, Auth, Key, MatrixRng, Model,
        E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_affine_zero_target_and_rne_share_original_ragged_source_bytes() {
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let first = bytes.scalar.layout.sources.len();
        let bytes = bytes
            .append(vec![
                ("affine/R".into(), 3, 2, 6),
                ("affine/X".into(), 3, 2, 2),
                ("affine/Y".into(), 3, 2, 2),
                ("affine/Z".into(), 3, 2, 2),
            ])
            .unwrap();
        assert!(bytes.live <= 1024);
        let relations = [Relation { raw: first, inputs: [(first + 1, 3), (first + 2, -2)] }];
        let pairs = [quantize::Pair { raw: first, output: first + 3, shift: 2 }];
        let count = range::required(10, range::Alphabet::Byte)
            + 32
            + bytes.table_rne_required(&plan, &pairs).unwrap();
        assert_eq!(count, 991);
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = bytes.layout_digest;
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(41);
        for fault in 0..4 {
            let mut raw: Vec<i64> = (0..6).map(|i| 3 * (2 * i - 5) - 2 * (3 - i)).collect();
            if fault == 1 {
                raw[0] += 1;
            } // same rounded output
            if fault == 2 {
                raw[0] += 3;
            } // coherent with changed X, but X in A is original
            let mut output: Vec<_> = raw
                .iter()
                .map(|&r| {
                    let a = r.abs();
                    let q = a / 4;
                    let rem = a % 4;
                    r.signum() * (q + i64::from(rem > 2 || (rem == 2 && q % 2 == 1)))
                })
                .collect();
            if fault == 3 {
                output[0] += 1;
            }
            let value = |id: usize, row: usize, col: usize| {
                let i = 2 * row + col;
                if id == first {
                    raw[i]
                } else if id == first + 1 {
                    2 * i as i64 - 5
                } else if id == first + 2 {
                    3 - i as i64
                } else if id == first + 3 {
                    output[i]
                } else {
                    0
                }
            };
            let read = |id: usize, row: usize, col: usize, b: usize| {
                let v = value(id, row, col) as u64;
                ((v >> (8 * b)) as u8) ^ if b + 1 == bytes.widths[id] { 128 } else { 0 }
            };
            let mut packed = vec![0u8; bytes.live];
            for (id, s) in bytes.scalar.layout.sources.iter().enumerate() {
                for row in 0..s.rows {
                    for col in 0..s.cols {
                        for b in 0..bytes.widths[id] {
                            packed[bytes.packed_offsets[id]
                                + (row * s.cols + col) * bytes.widths[id]
                                + b] = (value(id, row, col) as u64 >> (8 * b)) as u8;
                        }
                    }
                }
            }
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
                tokens: &[0, 1, 2],
            };
            let mut rng = MatrixRng::from_seed([123 + fault; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"public affine zero source target and original RNE", 100000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (zero, bias) =
                bytes.affine_zero_form(&plan, &context, &relations, &mut fs).unwrap();
            assert_eq!(fs.requests(), 3); // six joint live words, no private messages
            let (rne, pending) =
                bytes.prove_table_rne(&plan, &context, &pairs, read, &mut fs, &mut prows).unwrap();
            let (rp, forms, targets) = range::prove(
                &model,
                attempt,
                layout,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(forms), Vec::from(targets));
            forms.push(zero);
            targets.push(Auth::new(bias, Fp3::ZERO));
            let (rf, rs, rt) = bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
            forms.extend(rf);
            targets.extend(rt.into_iter().zip(rs).map(|(a, b)| Auth::new(a.x + b, a.m)));
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let (zero, bias) =
                bytes.affine_zero_form(&plan, &context, &relations, &mut fs).unwrap();
            let result =
                bytes.verify_table_rne(&plan, &context, &pairs, &rne, delta, &mut fs, &mut vrows);
            if fault == 3 {
                assert!(result.is_err(), "incorrect output passed RNE");
                continue;
            }
            let pending = result.unwrap();
            let (forms, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                bytes.live,
                range::Alphabet::Byte,
                &rp,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(forms), Vec::from(targets));
            forms.push(zero);
            targets.push(Key::new(delta * bias));
            let (rf, rs, rt) = bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
            forms.extend(rf);
            targets.extend(rt.into_iter().zip(rs).map(|(k, b)| Key::new(k.k + delta * b)));
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                layout,
                &forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 0 {
                assert_eq!(result.unwrap(), digest);
            } else {
                assert!(result.is_err(), "false affine raw or detached X passed same source PCS");
            }
            assert!(vrows.next().is_none());
            let invalid = [Relation { raw: first, inputs: [(first + 1, 1 << 31), (first + 2, 0)] }];
            let mut fs = start();
            assert!(bytes.affine_zero_form(&plan, &context, &invalid, &mut fs).is_err());
            assert_eq!(fs.requests(), 0);
        }
    }
}

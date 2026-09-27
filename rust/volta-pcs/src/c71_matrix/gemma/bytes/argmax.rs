//! Public token decisions from the ORIGINAL final i16 table in A.
//! A ranged unsigned-u16 slack proves each comparison, including lowest-ID
//! ties. This component does not prove the table's softcap/logits producer.

use super::*;
use crate::c71_matrix::gemma::{caller::P0Statement, rms::prefix};
use crate::c71_matrix::Fs;

impl Bytes {
    /// Slack is stored as biased-i16(s - 32768), so its two bytes encode
    /// the unsigned difference s verbatim. With both sources byte-ranged,
    /// s = Y[row,token]-Y[row,j]-[j<token] is an exact integer comparison.
    /// One common PCS public target, no new private MAC or per-token PCS.
    pub fn argmax_zero_form(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        output: usize,
        slack: usize,
        token_offset: usize,
        fs: &mut Fs,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        let y = self.scalar.layout.sources.get(output).ok_or("argmax output missing")?;
        let z = self.scalar.layout.sources.get(slack).ok_or("argmax slack missing")?;
        if output == slack
            || self.widths[output] != 2
            || self.widths[slack] != 2
            || [y.rows, y.cols] != [z.rows, z.cols]
            || y.rows == 0
            || y.rows > 50
            || !y.cols.is_power_of_two()
            || y.cols > 1 << 18
            || token_offset.checked_add(y.rows).is_none_or(|end| end > s.tokens.len())
            || s.tokens.len() > 150
            || self.scalar.weight_layout != plan.layout_digest
            || s.auxiliary_layout.layout.layout_digest != self.scalar.layout.layout_digest
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
        {
            return Err("argmax fixed sources, token slice or profile differs".into());
        }
        let tokens = &s.tokens[token_offset..token_offset + y.rows];
        if tokens.iter().any(|&t| t as usize >= y.cols) {
            return Err("argmax token outside vocabulary".into());
        }
        let mut frame =
            b"C71-argmax-zero-B12-v1;original-final-A;lowest-ID;unsigned-slack\0".to_vec();
        frame.extend(s.weights.roots()[0]);
        frame.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            frame.extend((gamma.len() as u64).to_le_bytes());
            frame.extend(gamma);
        }
        frame.extend(self.layout_digest);
        frame.extend(plan.layout_digest);
        frame.extend(s.quantization);
        frame.extend(s.attempt.encode());
        for n in [output, slack, token_offset, s.tokens.len()] {
            frame.extend((n as u64).to_le_bytes());
        }
        for t in s.tokens {
            frame.extend(t.to_le_bytes());
        }
        fs.set_phase(0x1500);
        fs.record(0xfd, &frame);
        let row: Vec<_> = (0..bits(y.rows)).map(|_| fs.fp3()).collect();
        let col: Vec<_> = (0..bits(y.cols)).map(|_| fs.fp3()).collect();
        // These are encoded words, so discard the signed interpretation's
        // bias. The two Y biases cancel; slack already encodes its u16 value.
        let (mut form, _) = self.word_form(slack, &row, &col, Fp3::ONE)?;
        form.extend(self.word_form(output, &row, &col, Fp3::ONE)?.0);
        let mut target = Fp3::ZERO;
        for (i, &token) in tokens.iter().enumerate() {
            let weight = eq_index(&row, i);
            form.extend(
                self.word_form(
                    output,
                    &prefix(i, 1, y.rows, &[]),
                    &prefix(token as usize, 1, y.cols, &[]),
                    Fp3::ZERO - weight,
                )?
                .0,
            );
            // MLE of [j<token], MSB prefix sum: O(log vocabulary), no LUT.
            let mut same = Fp3::ONE;
            for (bit, &r) in col.iter().enumerate() {
                if token as usize >> (col.len() - 1 - bit) & 1 == 1 {
                    target = target - weight * same * (Fp3::ONE - r);
                    same = same * r;
                } else {
                    same = same * (Fp3::ONE - r);
                }
            }
        }
        Ok((form, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{
        from_p3, gamma, linear, matrix_config, range, signed, AttemptContext, Auth, Key, MatrixRng,
        Model, E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_argmax_original_bytes_reject_wrong_token_tie_and_wrapped_slack() {
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let first = bytes.scalar.layout.sources.len();
        let bytes = bytes
            .append(vec![("argmax/Y".into(), 3, 4, 2), ("argmax/slack".into(), 3, 4, 2)])
            .unwrap();
        assert!(bytes.live <= 1024);
        let count = range::required(10, range::Alphabet::Byte) + 32;
        assert_eq!(count, 542);
        let profile = gamma(&matrix_config(32).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(47);
        let y = [[-32768i64, 32767, -1, 0], [7, 7, -3, 6], [0, 1, 4, 4]];
        for fault in 0..4 {
            let mut tokens = [3u32, 1, 0, 2]; // first token is outside decision slice
            if fault == 1 {
                tokens[1] = 0;
            } // smaller output, cannot wrap negative slack
            if fault == 2 {
                tokens[2] = 1;
            } // a maximum, but the earlier ID ties
            let scalar = |id, row: usize, col: usize| {
                if id == first {
                    return y[row][col];
                }
                if id == first + 1 {
                    let mut z = y[row][tokens[row + 1] as usize]
                        - y[row][col]
                        - i64::from(col < tokens[row + 1] as usize);
                    if fault == 3 && row == 2 && col == 3 {
                        z += 1;
                    }
                    return (z.rem_euclid(1 << 16)) - 32768;
                }
                0
            };
            let mut packed = vec![0u8; bytes.live];
            for (id, src) in bytes.scalar.layout.sources.iter().enumerate() {
                for row in 0..src.rows {
                    for col in 0..src.cols {
                        for b in 0..bytes.widths[id] {
                            packed[bytes.packed_offsets[id]
                                + (row * src.cols + col) * bytes.widths[id]
                                + b] = (scalar(id, row, col) as u64 >> (8 * b)) as u8;
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
                tokens: &tokens,
            };
            let mut rng = MatrixRng::from_seed([125 + fault; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"argmax original ranged source and public tokens", 100000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (form, target) =
                bytes.argmax_zero_form(&plan, &context, first, first + 1, 1, &mut fs).unwrap();
            assert_eq!(fs.requests(), 4);
            let (proof, forms, targets) = range::prove(
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
            forms.push(form);
            targets.push(Auth::new(target, Fp3::ZERO));
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
            let (form, target) =
                bytes.argmax_zero_form(&plan, &context, first, first + 1, 1, &mut fs).unwrap();
            let (forms, targets) = range::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(forms), Vec::from(targets));
            forms.push(form);
            targets.push(Key::new(delta * target));
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
            if fault == 0 {
                assert_eq!(result.unwrap(), digest);
                assert!(vrows.next().is_none());
            } else {
                assert!(result.is_err(), "incorrect decision/slack passed original A PCS");
                assert!(vrows.len() > 0);
            }
            let mut fs = start();
            for (out, slack, offset) in
                [(first, first, 1), (first, first + 1, 2), (usize::MAX, first + 1, 1)]
            {
                assert!(bytes
                    .argmax_zero_form(&plan, &context, out, slack, offset, &mut fs)
                    .is_err());
            }
            let invalid = P0Statement { tokens: &[0, 4, 0, 2], ..context };
            assert!(bytes.argmax_zero_form(&plan, &invalid, first, first + 1, 1, &mut fs).is_err());
            assert_eq!(fs.requests(), 0);
        }
        // Canonical-size form compilation only; no full A, PCS or softcap.
        let big = crate::c71_matrix::gemma::compile()
            .unwrap()
            .residual_sources_at(300)
            .unwrap()
            .attention
            .rope
            .gate_up
            .gelu
            .rms
            .bytes;
        let y_id = big.scalar.layout.sources.len();
        let big = big
            .append(vec![
                ("argmax/Y".into(), 50, 262144, 2),
                ("argmax/slack".into(), 50, 262144, 2),
            ])
            .unwrap();
        let root = crate::c71_matrix::C61Commitment::new(vec![[12; 32]]);
        let tokens: Vec<_> = (0..150).map(|i| i * 1709 % 262144).collect();
        let context = P0Statement {
            weights: &root,
            auxiliary: &root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &big.scalar,
            quantization: [5; 32],
            attempt,
            tokens: &tokens,
        };
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let mut fs = Fs::new(b"argmax 50 decisions metadata only", 1000);
        let (forms, _) =
            big.argmax_zero_form(&plan, &context, y_id, y_id + 1, 100, &mut fs).unwrap();
        assert_eq!(forms.len(), 56);
        assert_eq!(fs.requests(), 24);
    }
}

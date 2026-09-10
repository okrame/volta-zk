//! Original Pi is zero on future keys and padded queries. The public mask
//! acts on Boolean vertices before extension, never as mask(r)*Pi(r).

use super::*;
use crate::c71_matrix::gemma::{caller::P0Statement, rms::prefix};
use crate::c71_matrix::{linear, Fs};

/// Disjoint aligned query/key rectangles [q, height, k, width].
/// This component's <=450 keys fit wholly inside Gemma's local window.
pub(in crate::c71_matrix) fn forbidden_rectangles(
    new: usize,
    old: usize,
) -> Result<Vec<[usize; 4]>, String> {
    if new == 0 || new > 150 || old > 300 {
        return Err("causal mask exceeds the fixed-run window".into());
    }
    fn visit(out: &mut Vec<[usize; 4]>, new: usize, old: usize, [q, h, k, w]: [usize; 4]) {
        let keys = old + new;
        if k >= keys {
            return;
        }
        if k + w <= keys && (q >= new || k > old + q + h - 1) {
            out.push([q, h, k, w]);
        } else if q + h <= new && k + w - 1 <= old + q {
            // Entirely allowed: no zero constraint here.
        } else if h >= w && h > 1 {
            visit(out, new, old, [q, h / 2, k, w]);
            visit(out, new, old, [q + h / 2, h / 2, k, w]);
        } else if w > 1 {
            visit(out, new, old, [q, h, k, w / 2]);
            visit(out, new, old, [q, h, k + w / 2, w / 2]);
        }
    }
    let mut out = Vec::new();
    visit(&mut out, new, old, [0, new.next_power_of_two(), 0, (old + new).next_power_of_two()]);
    Ok(out)
}

impl Bytes {
    /// One PUBLIC known-bias target in the same ranged A PCS. No fresh MAC.
    /// The canonical caller supplies its original attention Pi source IDs.
    pub fn causal_zero_form(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        sources: &[usize],
        heads: usize,
        new: usize,
        old: usize,
        fs: &mut Fs,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        let rectangles = forbidden_rectangles(new, old)?;
        let rows = new.next_power_of_two();
        let keys = old + new;
        if sources.is_empty()
            || sources.len() > 60
            || !heads.is_power_of_two()
            || heads > 32
            || s.tokens.len() != new
            || self.scalar.weight_layout != plan.layout_digest
            || s.auxiliary_layout.layout.layout_digest != self.scalar.layout.layout_digest
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
        {
            return Err("causal mask fixed context or axes differ".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for &id in sources {
            let source = self.scalar.layout.sources.get(id).ok_or("mask source missing")?;
            if !seen.insert(id)
                || self.widths[id] != 2
                || [source.rows, source.cols] != [heads * rows, keys]
            {
                return Err("causal mask original Pi source shape or codec differs".into());
            }
        }
        // Each aligned rectangle lies within one canonical key tile; the
        // head/query source axis and the two-byte lane are powers of two.
        if rectangles.len() * sources.len() > linear::MAX_CUBES {
            return Err("causal mask source form exceeds cube capacity".into());
        }
        let mut frame = b"C71-causal-zero-B12-v1;original-Pi;head-query-key;vertex-mask\0".to_vec();
        frame.extend(s.weights.roots()[0]);
        frame.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            frame.extend((gamma.len() as u64).to_le_bytes());
            frame.extend(gamma);
        }
        frame.extend(plan.layout_digest);
        frame.extend(self.layout_digest);
        frame.extend(s.quantization);
        frame.extend(s.attempt.encode());
        for n in [heads, new, old, sources.len()] {
            frame.extend((n as u64).to_le_bytes());
        }
        for &id in sources {
            frame.extend((id as u64).to_le_bytes());
        }
        fs.set_phase(0x1700);
        fs.record(0xff, &frame);
        let layer: Vec<_> = (0..bits(sources.len())).map(|_| fs.fp3()).collect();
        let head: Vec<_> = (0..bits(heads)).map(|_| fs.fp3()).collect();
        let query: Vec<_> = (0..bits(rows)).map(|_| fs.fp3()).collect();
        let key: Vec<_> = (0..bits(keys)).map(|_| fs.fp3()).collect();
        let (mut form, mut bias) = (Vec::new(), Fp3::ZERO);
        for (l, &id) in sources.iter().enumerate() {
            for &[q, h, k, w] in &rectangles {
                let qb = bits(rows) - bits(h);
                let kb = bits(keys) - bits(w);
                let coefficient = eq_index(&layer, l)
                    * eq_index(&query[..qb], q / h)
                    * eq_index(&key[..kb], k / w);
                let row: Vec<_> =
                    head.iter().copied().chain(prefix(q, h, rows, &query[qb..])).collect();
                let col = prefix(k, w, keys, &key[kb..]);
                let (f, b) = self.word_form(id, &row, &col, coefficient)?;
                debug_assert!(f.len() <= 1);
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
        eq, from_p3, gamma, matrix_config, range, signed, AttemptContext, Auth, Key, MatrixRng,
        Model, E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_causal_mask_uses_original_pi_at_vertices_and_same_ranged_pcs() {
        // Full canonical mask coverage, including the ragged physical key
        // edge, is public metadata: no full source body or forward execution.
        for (old, count) in [(0, 398), (150, 386), (300, 446)] {
            let rectangles = forbidden_rectangles(150, old).unwrap();
            assert_eq!(rectangles.len(), count);
            let mut cover = vec![0u8; 256 * (old + 150)];
            for [q, h, k, w] in rectangles {
                assert!(h.is_power_of_two() && w.is_power_of_two() && q % h == 0 && k % w == 0);
                for row in q..q + h {
                    for col in k..k + w {
                        cover[row * (old + 150) + col] += 1;
                    }
                }
            }
            for row in 0..256 {
                for col in 0..old + 150 {
                    assert_eq!(
                        cover[row * (old + 150) + col],
                        u8::from(row >= 150 || col > old + row)
                    );
                }
            }
        }
        assert!(forbidden_rectangles(0, 0).is_err());
        assert!(forbidden_rectangles(151, 0).is_err());
        assert!(forbidden_rectangles(150, 301).is_err());
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let first = bytes.scalar.layout.sources.len();
        let bytes =
            bytes.append(vec![("mask/Pi0".into(), 8, 5, 2), ("mask/Pi1".into(), 8, 5, 2)]).unwrap();
        assert!(bytes.live <= 1024);
        let profile = gamma(&matrix_config(32).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let count = range::required(10, range::Alphabet::Byte) + 32;
        assert_eq!(count, 542);
        let delta = signed(53);
        for fault in 0..3 {
            let value = |id, row: usize, col: usize| -> i64 {
                if id < first {
                    return 0;
                }
                let q = row % 4;
                if fault == 1 && id == first && row == 0 && col == 3 {
                    return 1;
                }
                if fault == 2 && id == first + 1 && row == 7 && col == 1 {
                    return -1;
                }
                if q < 3 && col <= 2 + q {
                    (1 + row + col) as i64
                } else {
                    0
                }
            };
            let mut packed = vec![0u8; bytes.live];
            for (id, source) in bytes.scalar.layout.sources.iter().enumerate() {
                for row in 0..source.rows {
                    for col in 0..source.cols {
                        for b in 0..bytes.widths[id] {
                            packed[bytes.packed_offsets[id]
                                + (row * source.cols + col) * bytes.widths[id]
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
                quantization: [7; 32],
                attempt,
                tokens: &[0, 1, 2],
            };
            let mut rng = MatrixRng::from_seed([138 + fault; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"vertex causal mask original Pi source", 100000);
            let mut fs = start();
            let (form, bias) = bytes
                .causal_zero_form(&plan, &context, &[first, first + 1], 2, 3, 2, &mut fs)
                .unwrap();
            assert_eq!(fs.requests(), 7); // layer, head, two query and three key bits
            let literal = form.iter().fold(Fp3::ZERO, |v, c| {
                v + c.coefficient
                    * eq(&c.point).iter().enumerate().fold(Fp3::ZERO, |s, (i, &e)| {
                        s + e * from_p3(model.polynomial().as_slice()[c.offset + i].into())
                    })
            });
            assert_eq!(literal == bias, fault == 0);
            // A product mask(r)*Pi(r) would generally constrain live values
            // too; the honest nonzero values above must remain accepted.
            let mut prows = rows.into_iter();
            let (range_proof, f, t) = range::prove(
                &model,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(f), Vec::from(t));
            forms.push(form);
            targets.push(Auth::new(bias, Fp3::ZERO));
            let (proof, digest) = linear::prove(
                &model,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(prows.len(), 0);
            let mut fs = start();
            let (form, bias) = bytes
                .causal_zero_form(&plan, &context, &[first, first + 1], 2, 3, 2, &mut fs)
                .unwrap();
            let mut vrows = keys.into_iter();
            let (f, t) = range::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (mut forms, mut targets) = (Vec::from(f), Vec::from(t));
            forms.push(form);
            targets.push(Key::new(delta * bias));
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &proof,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 0 {
                assert_eq!(result.unwrap(), digest);
            } else {
                assert!(result.is_err());
            }
            let mut fs = start();
            assert!(bytes
                .causal_zero_form(&plan, &context, &[first, first], 2, 3, 2, &mut fs)
                .is_err());
            assert!(bytes.causal_zero_form(&plan, &context, &[first], 1, 3, 2, &mut fs).is_err());
            assert_eq!(fs.requests(), 0);
        }
    }
}

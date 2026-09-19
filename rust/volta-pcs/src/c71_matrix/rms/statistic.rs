//! RMS S=sum X² through the existing cubic P0 kernel. The selected view of
//! X is zero outside its live rows/columns; ORIGINAL S/X MACs still need A.

use super::super::*;

component_wire!(Proof { statistic, reduction });

pub(in super::super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub shape: [usize; 2],
}

pub(in super::super) struct Proof {
    statistic: Fp3,
    reduction: p0::Proof,
}

pub(in super::super) struct Pending<T> {
    pub statistic_point: Vec<Fp3>,
    pub statistic: T,
    pub input_point: Vec<Fp3>,
    // Both X endpoints open the SAME selected source view. The triple goes
    // to the caller's COMMON product batch; this kernel grants no acceptance.
    pub inputs: [T; 3],
}

impl Statement<'_> {
    fn dimensions(&self) -> Result<[usize; 2], String> {
        if self.shape[0] == 0
            || self.shape[0] > 8192
            || self.shape[1] == 0
            || self.shape[1] > 5376
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 RMS statistic statement differs".into());
        }
        let bits = self.shape.map(|n| n.next_power_of_two().ilog2() as usize);
        if bits[0] + bits[1] > 26 {
            return Err("B12 RMS statistic exceeds D26".into());
        }
        Ok(bits)
    }

    pub fn required(&self) -> Result<usize, String> {
        let [r, c] = self.dimensions()?;
        Ok(1 + p0::required(r + c, true))
    }

    fn bind(&self, row_bits: usize, fs: &mut Fs) -> Vec<Fp3> {
        let mut bytes =
            b"C71-RMS-statistic-B12-v1;selected-X;row-col-MSB;original-S-X-MACs".to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        for n in self.shape {
            bytes.extend((n as u64).to_le_bytes());
        }
        fs.set_phase(0xb00);
        fs.record(0x90, &bytes);
        (0..row_bits).map(|_| fs.fp3()).collect()
    }
}

pub(in super::super) fn prove(
    s: &Statement<'_>,
    get_x: impl Fn(usize, usize) -> i16,
    get_s: impl Fn(usize) -> [u8; 6],
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let [r, c] = s.dimensions()?;
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 RMS statistic prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let statistic_point = s.bind(r, fs);
    let value =
        eq(&statistic_point).iter().take(s.shape[0]).enumerate().fold(Fp3::ZERO, |v, (row, &a)| {
            let word = get_s(row)
                .iter()
                .enumerate()
                .fold(0i64, |v, (b, &u)| v + (i64::from(u) << (8 * b)));
            v + a * signed(word - (1 << 47))
        });
    let (wire, original) = range::authenticate([value], &mut rows);
    record_values(fs, 0x91, &wire);
    let mut point = statistic_point.clone();
    point.extend(vec![signed(2).inv(); c]);
    let x: Vec<_> = (0..1usize << (r + c))
        .map(|i| {
            let (row, col) = (i >> c, i % (1 << c));
            if row < s.shape[0] && col < s.shape[1] {
                signed(i64::from(get_x(row, col)))
            } else {
                Fp3::ZERO
            }
        })
        .collect();
    // Sum EQ(half,col) X² is S/2^c. The only inverse is this PUBLIC power
    // of two; do not take a square or RMS of an already folded input.
    let target = original[0].scale(signed(1 << c).inv());
    let (reduction, input_point, inputs) =
        p0::prove(x.clone(), x, target, Some(&point), fs, &mut rows)?;
    debug_assert!(rows.next().is_none());
    Ok((
        Proof { statistic: wire[0], reduction },
        Pending { statistic_point, statistic: original[0], input_point, inputs },
    ))
}

pub(in super::super) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<Pending<Key>, String> {
    let [r, c] = s.dimensions()?;
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 RMS statistic verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let statistic_point = s.bind(r, fs);
    let original = range::correct([proof.statistic], delta, &mut rows)[0];
    record_values(fs, 0x91, &[proof.statistic]);
    let mut point = statistic_point.clone();
    point.extend(vec![signed(2).inv(); c]);
    let (input_point, inputs) = p0::verify(
        r + c,
        original.scale(signed(1 << c).inv()),
        Some(&point),
        &proof.reduction,
        delta,
        fs,
        &mut rows,
    )?;
    debug_assert!(rows.next().is_none());
    Ok(Pending { statistic_point, statistic: original, input_point, inputs })
}

#[cfg(test)]
mod tests {
    use super::super::gkr;
    use super::*;
    use linear::Cube;
    use rand_010::RngExt;

    fn biased(value: i64, bytes: usize) -> Vec<u8> {
        let word = (value + (1 << (8 * bytes - 1))) as u64;
        (0..bytes).map(|b| (word >> (8 * b)) as u8).collect()
    }

    fn byte_form(
        offset: usize,
        point: &[Fp3],
        bytes: usize,
        byte: usize,
        coefficient: Fp3,
    ) -> Cube {
        let mut point = point.to_vec();
        for b in (0..bytes.next_power_of_two().ilog2()).rev() {
            point.push(if byte >> b & 1 == 1 { Fp3::ONE } else { Fp3::ZERO });
        }
        Cube { offset, point, coefficient }
    }

    fn word_form(offset: usize, point: &[Fp3], bytes: usize) -> Vec<Cube> {
        (0..bytes).map(|b| byte_form(offset, point, bytes, b, signed(1 << (8 * b)))).collect()
    }

    fn shift(point: &[Fp3], bytes: usize) -> Fp3 {
        signed(1 << (8 * bytes - 1)) * byte_function::live_mass(3, &point[1..])
    }

    // One physical S per ROW. Every RMS channel broadcasts those SAME six
    // bytes; no independently committed copy of the denominator is accepted.
    fn rms_form(point: &[Fp3]) -> Vec<Cube> {
        let cell = &point[..3];
        let lanes = eq(&point[3..]);
        let mut result = Vec::new();
        for b in 0..4 {
            result.push(byte_form(0, cell, 4, b, lanes[b]));
        }
        for b in 0..6 {
            result.push(byte_form(
                32,
                &cell[..1],
                6,
                b,
                lanes[4 + b] * byte_function::live_mass(3, &cell[1..]),
            ));
        }
        for b in 0..2 {
            result.push(byte_form(64, cell, 2, b, lanes[10 + b]));
        }
        result
    }

    #[test]
    fn c71_b12_rms_statistic_and_weighted_product_share_original_w_x_s_y_sources() {
        let n = 32;
        let x = [[1i16, -2, 3, 0], [-3, 0, 1, 0]];
        let mut w = vec![0; n * n];
        w[..4].copy_from_slice(&[2, -1, 3, 0]);
        let model = Model::new(n, w.clone()).unwrap();
        let profile = gamma(&matrix_config(n).unwrap());
        let programs = [super::super::compile(3, 0, 0, 0, true).unwrap()];
        let assignments = [Some(0), Some(0), Some(0), None, Some(0), Some(0), Some(0), None];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        let layout = [51; 32];
        for fault in 0..3 {
            let mut used_w = w[..4].to_vec();
            if fault == 2 {
                used_w[0] = 3;
            }
            let mut s = [14i64, 10];
            if fault == 1 {
                s[0] = 15;
            }
            let y = [[1i64, 1, 4, 0], [if fault == 2 { -5 } else { -3 }, 0, 2, 0]];
            let mut p = [[0i64; 4]; 2];
            // Public source layout: P[2,4,4] at 0, S[2,8] at 32,
            // X[2,4,2] at 48, Y[2,4,2] at 64; missing columns/bytes zero.
            let mut auxiliary = vec![0i16; n * n];
            for row in 0..2 {
                for (b, u) in biased(s[row], 6).into_iter().enumerate() {
                    auxiliary[32 + 8 * row + b] = i16::from(u);
                }
                for col in 0..3 {
                    p[row][col] = i64::from(x[row][col]) * i64::from(used_w[col]);
                    for (offset, value, bytes) in
                        [(0, p[row][col], 4), (48, i64::from(x[row][col]), 2), (64, y[row][col], 2)]
                    {
                        for (b, u) in biased(value, bytes).into_iter().enumerate() {
                            auxiliary[offset + (4 * row + col) * bytes + b] = i16::from(u);
                        }
                    }
                }
            }
            let aux = Model::new(n, auxiliary).unwrap();
            let ss = Statement {
                root: &aux.root,
                profile: &profile,
                view: [52; 32],
                attempt,
                shape: [2, 3],
            };
            let gs = gkr::Statement {
                root: &aux.root,
                profile: &profile,
                view: [53; 32],
                attempt,
                programs: &programs,
                assignments: gkr::Assignments::dense(&assignments),
            };
            let mut context =
                b"B12 exact weighted RMS; one W and one shared X/P/S/Y byte source".to_vec();
            context.extend(model.root.roots()[0]);
            context.extend(aux.root.roots()[0]);
            context.extend(layout);
            context.extend(attempt.encode());
            let start = || Fs::new(&context, 100_000);
            let count = 12 + ss.required().unwrap() + 1 + gs.required().unwrap() + 269 + 510 + 64;
            assert_eq!(count, 7761);
            let mut rng = MatrixRng::from_seed([128; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let mut fs = start();
            let mut prows = rows.into_iter();
            let output: Vec<_> = (0..3).map(|_| fs.fp3()).collect();
            let value =
                p.iter().flatten().zip(eq(&output)).fold(Fp3::ZERO, |v, (&p, r)| v + signed(p) * r);
            let (cut_wire, cut) = range::authenticate([value], &mut prows);
            record_values(&mut fs, 0x92, &cut_wire);
            let xbar: Vec<_> = (0..4)
                .map(|col| {
                    (0..2)
                        .zip(eq(&output[..1]))
                        .fold(Fp3::ZERO, |v, (row, r)| v + r * signed(i64::from(x[row][col])))
                })
                .collect();
            let (product_proof, inner, product) = p0::prove(
                xbar,
                used_w.iter().map(|&w| signed(i64::from(w))).collect(),
                cut[0],
                Some(&output[1..]),
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let input: Vec<_> = output[..1].iter().chain(&inner).copied().collect();
            let (stat_proof, stat) = prove(
                &ss,
                |r, c| x[r][c],
                |r| biased(s[r], 6).try_into().unwrap(),
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let products =
                range::prove_products(&[product, stat.inputs], prows.next().unwrap(), &mut fs);
            let (rms_proof, rms_point, rms) = gkr::prove(
                &gs,
                |cell| {
                    let (row, col) = (cell / 4, cell % 4);
                    biased(p[row][col], 4)
                        .into_iter()
                        .chain(biased(s[row], 6))
                        .chain(biased(y[row][col], 2))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap()
                },
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (wrange, wforms, wtargets) =
                range::prove(&model, attempt, layout, 4, 7, &mut fs, &mut prows).unwrap();
            let mut wforms = Vec::from(wforms);
            wforms.push(vec![Cube { offset: 0, point: inner, coefficient: Fp3::ONE }]);
            let wtargets = [wtargets[0], wtargets[1], product[1]];
            let (wpcs, wdigest) =
                linear::prove(&model, attempt, layout, &wforms, &wtargets, &mut fs, &mut prows)
                    .unwrap();
            let (arange, aforms, atargets) =
                range::prove(&aux, attempt, layout, 80, range::Alphabet::Byte, &mut fs, &mut prows)
                    .unwrap();
            let mut aforms = Vec::from(aforms);
            let mut atargets = Vec::from(atargets);
            for (form, shift, a) in [
                (word_form(0, &output, 4), shift(&output, 4), cut[0]),
                (word_form(48, &input, 2), shift(&input, 2), product[0]),
                (word_form(32, &stat.statistic_point, 6), signed(1 << 47), stat.statistic),
                (word_form(48, &stat.input_point, 2), shift(&stat.input_point, 2), stat.inputs[0]),
                (word_form(48, &stat.input_point, 2), shift(&stat.input_point, 2), stat.inputs[1]),
                (rms_form(&rms_point), Fp3::ZERO, rms),
            ] {
                aforms.push(form);
                atargets.push(Auth::new(a.x + shift, a.m));
            }
            let (apcs, adigest) =
                linear::prove(&aux, attempt, layout, &aforms, &atargets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let output: Vec<_> = (0..3).map(|_| fs.fp3()).collect();
            let cut = range::correct(cut_wire, delta, &mut vrows)[0];
            record_values(&mut fs, 0x92, &cut_wire);
            let (inner, product) =
                p0::verify(2, cut, Some(&output[1..]), &product_proof, delta, &mut fs, &mut vrows)
                    .unwrap();
            let input: Vec<_> = output[..1].iter().chain(&inner).copied().collect();
            let checked = verify(&ss, &stat_proof, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert!(matches!(checked,Err(ref e) if e == "B12 P0 sumcheck MAC rejected"));
                continue;
            }
            let stat = checked.unwrap();
            range::verify_products(
                &[product, stat.inputs],
                vrows.next().unwrap(),
                products,
                delta,
                &mut fs,
            )
            .unwrap();
            let (rms_point, rms) =
                gkr::verify(&gs, &rms_proof, delta, &mut fs, &mut vrows).unwrap();
            let (wforms, wtargets) = range::verify(
                n,
                &model.root,
                attempt,
                layout,
                4,
                7,
                &wrange,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut wforms = Vec::from(wforms);
            wforms.push(vec![Cube { offset: 0, point: inner, coefficient: Fp3::ONE }]);
            let wtargets = [wtargets[0], wtargets[1], product[1]];
            let checked = linear::verify(
                n,
                &model.root,
                attempt,
                layout,
                &wforms,
                &wtargets,
                &wpcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert_eq!(checked.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                continue;
            }
            assert_eq!(checked.unwrap(), wdigest);
            let (aforms, atargets) = range::verify(
                n,
                &aux.root,
                attempt,
                layout,
                80,
                range::Alphabet::Byte,
                &arange,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut aforms = Vec::from(aforms);
            let mut atargets = Vec::from(atargets);
            for (form, shift, k) in [
                (word_form(0, &output, 4), shift(&output, 4), cut),
                (word_form(48, &input, 2), shift(&input, 2), product[0]),
                (word_form(32, &stat.statistic_point, 6), signed(1 << 47), stat.statistic),
                (word_form(48, &stat.input_point, 2), shift(&stat.input_point, 2), stat.inputs[0]),
                (word_form(48, &stat.input_point, 2), shift(&stat.input_point, 2), stat.inputs[1]),
                (rms_form(&rms_point), Fp3::ZERO, rms),
            ] {
                aforms.push(form);
                atargets.push(Key::new(k.k + delta * shift));
            }
            assert_eq!(
                linear::verify(
                    n, &aux.root, attempt, layout, &aforms, &atargets, &apcs, delta, &mut fs,
                    &mut vrows
                )
                .unwrap(),
                adigest
            );
            assert!(vrows.next().is_none());
        }
    }
}

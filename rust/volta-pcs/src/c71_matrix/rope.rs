//! Joint raw RoPE from fixed public Q30 tables. The shared linear sumcheck
//! returns ORIGINAL raw/input MACs for the caller's SAME ranged byte PCS.

use super::*;

pub(super) struct Block {
    pub rows: usize, // dyadic token interval; columns are head || half || pair
    pub heads: usize,
    pub width: usize,
    pub position: usize, // first ABSOLUTE public position, not a witness offset
    pub family: usize,
}

pub(super) struct Table<'a> {
    pub position: usize,
    pub rows: &'a [Vec<[i32; 2]>], // verifier's certified table; omitted pairs are (2^30,0)
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
    raw: Fp3,
    rounds: Vec<[Fp3; 4]>,
    terminal: [Fp3; 2],
}

pub(super) struct Pending<T> {
    pub raw_point: Vec<Fp3>,
    pub input_point: Vec<Fp3>,
    pub originals: [T; 2], // raw R and source Y; no acceptance without BOTH closures
}

impl Statement<'_> {
    fn dimensions(&self) -> Result<(usize, usize), String> {
        if self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
            || self.blocks.is_empty()
            || self.blocks.len() > 512
            || self.tables.is_empty()
            || self.tables.len() > 2
        {
            return Err("RoPE source context or public block list differs".into());
        }
        for table in self.tables {
            if table.rows.is_empty()
                || table.rows.len() > 4096
                || table.position > 4095
                || table.position + table.rows.len() > 4096
                || table.rows[0].is_empty()
                || table.rows[0].len() > 256
                || table.rows.iter().any(|r| {
                    r.len() != table.rows[0].len()
                        || r.iter().flatten().any(|&x| !(-(1 << 30)..=(1 << 30)).contains(&x))
                })
            {
                return Err("RoPE public Q30 table differs".into());
            }
        }
        let mut cells = 0usize;
        for b in self.blocks {
            let t = self.tables.get(b.family).ok_or("RoPE coefficient family missing")?;
            if !b.rows.is_power_of_two()
                || b.rows > 4096
                || !b.heads.is_power_of_two()
                || b.heads > 32
                || !b.width.is_power_of_two()
                || !(2..=512).contains(&b.width)
                || b.position < t.position
                || b.position > 4095
                || b.position + b.rows > t.position + t.rows.len()
                || t.rows[0].len() > b.width / 2
            {
                return Err("RoPE block axes, positions or active pairs differ".into());
            }
            let size = b.rows * b.heads * b.width;
            if cells % size != 0 {
                return Err("RoPE blocks must be aligned dyadic intervals".into());
            }
            cells = cells.checked_add(size).ok_or("RoPE cell count overflow")?;
        }
        if cells > 1 << 15 {
            return Err("RoPE joint caller exceeds native D15".into());
        }
        Ok((cells, cells.next_power_of_two().ilog2() as usize))
    }

    pub fn required(&self) -> Result<usize, String> {
        Ok(3 * self.dimensions()?.1 + 2)
    }

    fn coefficient(&self, b: &Block, row: usize, pair: usize) -> [Fp3; 2] {
        let t = &self.tables[b.family];
        t.rows[b.position + row - t.position]
            .get(pair)
            .copied()
            .unwrap_or([1 << 30, 0])
            .map(|x| signed(i64::from(x)))
    }

    fn bind(&self, c: usize, fs: &mut Fs) -> Vec<Fp3> {
        let mut bytes =
            b"C71-RoPE-Q30-joint-B12-v1;dyadic-MSB;raw-and-Y-original;tail-zero\0".to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        bytes.extend((self.tables.len() as u64).to_le_bytes());
        for t in self.tables {
            for n in [t.position, t.rows.len(), t.rows[0].len()] {
                bytes.extend((n as u64).to_le_bytes());
            }
            for row in t.rows {
                for pair in row {
                    for x in pair {
                        bytes.extend(x.to_le_bytes());
                    }
                }
            }
        }
        bytes.extend((self.blocks.len() as u64).to_le_bytes());
        for b in self.blocks {
            for n in [b.rows, b.heads, b.width, b.position, b.family] {
                bytes.extend((n as u64).to_le_bytes());
            }
        }
        fs.set_phase(0x1100);
        fs.record(0xe0, &bytes);
        (0..c).map(|_| fs.fp3()).collect()
    }

    // Public adjoint on Boolean vertices. Rotation swaps the FULL half-head;
    // inactive pairs still multiply by 2^30 before the single output RNE.
    fn fill(&self, r: &[Fp3]) -> Vec<Fp3> {
        let mut result = vec![Fp3::ZERO; 1 << r.len()];
        let mut offset = 0;
        for b in self.blocks {
            let (rb, hb, lb) =
                (b.rows.ilog2() as usize, b.heads.ilog2() as usize, b.width.ilog2() as usize);
            let high = r.len() - rb - hb - lb;
            let prefix = gemma::eq_index(&r[..high], offset / (b.rows * b.heads * b.width));
            let rt = eq(&r[high..high + rb]);
            let rh = eq(&r[high + rb..high + rb + hb]);
            let half = r[high + rb + hb];
            let rj = eq(&r[high + rb + hb + 1..]);
            for (t, &tw) in rt.iter().enumerate() {
                for (h, &hw) in rh.iter().enumerate() {
                    for (j, &jw) in rj.iter().enumerate() {
                        let [cos, sin] = self.coefficient(b, t, j);
                        let a = prefix * tw * hw * jw;
                        result[offset + (t * b.heads + h) * b.width + j] =
                            a * ((Fp3::ONE - half) * cos + half * sin);
                        result[offset + (t * b.heads + h) * b.width + b.width / 2 + j] =
                            a * (half * cos + (half - Fp3::ONE) * sin);
                    }
                }
            }
            offset += b.rows * b.heads * b.width;
        }
        result
    }

    // Evaluate the SAME adjoint without any private source or dense field
    // table. EQ*coefficient products are formed on Boolean token/pair indices.
    fn at(&self, r: &[Fp3], u: &[Fp3]) -> Fp3 {
        let mut result = Fp3::ZERO;
        let mut offset = 0;
        for b in self.blocks {
            let (rb, hb, lb) =
                (b.rows.ilog2() as usize, b.heads.ilog2() as usize, b.width.ilog2() as usize);
            let high = r.len() - rb - hb - lb;
            let prefix = gemma::eq_index(&r[..high], offset / (b.rows * b.heads * b.width))
                * gemma::eq_index(&u[..high], offset / (b.rows * b.heads * b.width));
            let (rt, ut) = (eq(&r[high..high + rb]), eq(&u[high..high + rb]));
            let eq2 = |x, y| (Fp3::ONE - x) * (Fp3::ONE - y) + x * y;
            let head = r[high + rb..high + rb + hb]
                .iter()
                .zip(&u[high + rb..high + rb + hb])
                .fold(Fp3::ONE, |v, (&x, &y)| v * eq2(x, y));
            let (rh, uh) = (r[high + rb + hb], u[high + rb + hb]);
            let (rj, uj) = (eq(&r[high + rb + hb + 1..]), eq(&u[high + rb + hb + 1..]));
            let (mut cos, mut sin) = (Fp3::ZERO, Fp3::ZERO);
            for t in 0..b.rows {
                for j in 0..b.width / 2 {
                    let [c, s] = self.coefficient(b, t, j);
                    let a = rt[t] * ut[t] * rj[j] * uj[j];
                    cos += a * c;
                    sin += a * s;
                }
            }
            result += prefix * head * (eq2(rh, uh) * cos + (rh - uh) * sin);
            offset += b.rows * b.heads * b.width;
        }
        result
    }
}

pub(super) fn prove(
    s: &Statement<'_>,
    read: impl Fn(usize) -> ([u8; 6], i16),
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let (cells, c) = s.dimensions()?;
    let count = 3 * c + 2;
    if correlations.len() < count {
        return Err("RoPE prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let raw_point = s.bind(c, fs);
    let mut y = vec![Fp3::ZERO; 1 << c];
    let mut value = Fp3::ZERO;
    for (i, w) in eq(&raw_point).into_iter().take(cells).enumerate() {
        let (raw, input) = read(i);
        let raw = raw.iter().enumerate().fold(0i64, |v, (b, &u)| v + (i64::from(u) << (8 * b)));
        value += w * signed(raw - (1 << 47));
        y[i] = signed(i64::from(input));
    }
    let (wire, raw) = range::authenticate([value], &mut rows);
    record_values(fs, 0xe1, &wire);
    let (rounds, input_point, target, y, f) =
        prove_product(y, s.fill(&raw_point), raw[0], fs, &mut rows);
    let (correction, input) = range::authenticate([y], &mut rows);
    let terminal = [correction[0], target.m - f * input[0].m];
    fs.set_phase(0x1110);
    record_values(fs, 0xe2, &terminal);
    debug_assert!(rows.next().is_none());
    Ok((
        Proof { raw: wire[0], rounds, terminal },
        Pending { raw_point, input_point, originals: [raw[0], input[0]] },
    ))
}

pub(super) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<Pending<Key>, String> {
    let (_, c) = s.dimensions()?;
    let count = 3 * c + 2;
    if correlations.len() < count || proof.rounds.len() != c {
        return Err("RoPE proof shape or capacity differs".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let raw_point = s.bind(c, fs);
    let raw = range::correct([proof.raw], delta, &mut rows)[0];
    record_values(fs, 0xe1, &[proof.raw]);
    let (target, input_point) = verify_product(&proof.rounds, raw, delta, fs, &mut rows)?;
    let input = range::correct([proof.terminal[0]], delta, &mut rows)[0];
    if target.k - s.at(&raw_point, &input_point) * input.k != proof.terminal[1] {
        return Err("RoPE original linear endpoint MAC rejected".into());
    }
    fs.set_phase(0x1110);
    record_values(fs, 0xe2, &proof.terminal);
    debug_assert!(rows.next().is_none());
    Ok(Pending { raw_point, input_point, originals: [raw, input] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::RngExt;

    fn word_form(offset: usize, p: &[Fp3], width: usize) -> (Vec<Cube>, Fp3) {
        let lane_bits = width.next_power_of_two().ilog2() as usize;
        let forms = (0..width)
            .map(|b| {
                let mut point = p.to_vec();
                point.extend((0..lane_bits).rev().map(|j| {
                    if b >> j & 1 == 1 {
                        Fp3::ONE
                    } else {
                        Fp3::ZERO
                    }
                }));
                Cube { offset, point, coefficient: signed(1 << (8 * b)) }
            })
            .collect();
        (forms, signed(1 << (8 * width - 1)) * byte_function::live_mass(24, p))
    }

    #[test]
    fn c71_b12_rope_joint_adjoint_and_original_raw_y_close_same_ranged_source() {
        // Restricted active pair j=0 from the exact canonical Q30 recipe.
        // The second pair is inactive but still uses C=2^30, S=0.
        let rows = vec![
            vec![[1073741824, 0]],
            vec![[580145183, 903522590]],
            vec![[-446834263, 976350678]],
        ];
        let tables = [Table { position: 0, rows: &rows }];
        let blocks = [
            Block { rows: 2, heads: 2, width: 4, position: 0, family: 0 },
            Block { rows: 1, heads: 2, width: 4, position: 2, family: 0 },
        ];
        let original: Vec<i16> = (0..24).map(|i| (i % 7) as i16 - 3).collect();
        let raw = |y: &[i16]| -> Vec<i64> {
            (0..24)
                .map(|i| {
                    let (t, head, lane) = (i / 8, (i % 8) / 4, i % 4);
                    let j = lane % 2;
                    let [c, s] = if j == 0 { rows[t][0] } else { [1 << 30, 0] };
                    let (a, b) = (
                        i64::from(y[t * 8 + head * 4 + j]),
                        i64::from(y[t * 8 + head * 4 + 2 + j]),
                    );
                    if lane < 2 {
                        i64::from(c) * a - i64::from(s) * b
                    } else {
                        i64::from(s) * a + i64::from(c) * b
                    }
                })
                .collect()
        };
        let source = |y: &[i16], r: &[i64]| {
            let mut values = vec![0; 1024];
            for i in 0..24 {
                let raw = (r[i] + (1 << 47)) as u64;
                for b in 0..6 {
                    values[8 * i + b] = i16::from((raw >> (8 * b)) as u8);
                }
                let input = (i32::from(y[i]) + 32768) as u16;
                for b in 0..2 {
                    values[256 + 2 * i + b] = i16::from((input >> (8 * b)) as u8);
                }
            }
            values
        };
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = [79; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(37);
        for fault in 0..3 {
            let mut y = original.clone();
            if fault == 2 {
                y[0] += 1;
            }
            let mut r = raw(&y);
            if fault == 1 {
                r[0] += 1;
            }
            let model = Model::new(
                32,
                if fault == 2 { source(&original, &raw(&original)) } else { source(&y, &r) },
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
            assert_eq!(s.required().unwrap(), 17);
            let q: Vec<_> = (0..5).map(|i| signed(i + 3)).collect();
            let u: Vec<_> = (0..5).map(|i| signed(i + 9)).collect();
            let f = s.fill(&q);
            assert_eq!(s.at(&q, &u), f.iter().zip(eq(&u)).fold(Fp3::ZERO, |v, (&f, w)| v + f * w));
            if fault == 0 {
                assert_eq!(
                    r.iter().zip(eq(&q)).fold(Fp3::ZERO, |v, (&r, w)| v + signed(r) * w),
                    y.iter().zip(f).fold(Fp3::ZERO, |v, (&y, f)| v + signed(i64::from(y)) * f)
                );
            }
            let count = s.required().unwrap() + 510 + 32;
            assert_eq!(count, 559);
            let mut rng = MatrixRng::from_seed([163; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"joint Q30 RoPE with original byte source", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (proof, p) = prove(
                &s,
                |i| {
                    let raw = (r[i] + (1 << 47)) as u64;
                    (std::array::from_fn(|b| (raw >> (8 * b)) as u8), y[i])
                },
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(fs.requests(), 10);
            let (range_proof, ranged, targets) = range::prove(
                &model,
                attempt,
                layout,
                320,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let forms = [word_form(0, &p.raw_point, 6), word_form(256, &p.input_point, 2)];
            let all_forms: Vec<_> =
                ranged.into_iter().chain(forms.iter().map(|(f, _)| f.clone())).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(
                    p.originals.into_iter().zip(&forms).map(|(a, (_, s))| Auth::new(a.x + *s, a.m)),
                )
                .collect();
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &all_forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let result = verify(&s, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert!(result.is_err(), "wrong RoPE raw passed the linear GKR");
                continue;
            }
            let p = result.unwrap();
            assert_eq!(fs.requests(), 10);
            let (ranged, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                320,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let forms = [word_form(0, &p.raw_point, 6), word_form(256, &p.input_point, 2)];
            let all_forms: Vec<_> =
                ranged.into_iter().chain(forms.iter().map(|(f, _)| f.clone())).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(
                    p.originals
                        .into_iter()
                        .zip(&forms)
                        .map(|(k, (_, s))| Key::new(k.k + delta * (*s))),
                )
                .collect();
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                layout,
                &all_forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert!(result.is_err(), "changed Y and consistent raw detached from A");
            } else {
                assert_eq!(result.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
            let mut exhausted = vec![Auth::ZERO; 16].into_iter();
            assert!(prove(&s, |_| panic!("exhaustion read witness"), &mut start(), &mut exhausted)
                .is_err());
            assert_eq!(exhausted.len(), 16);
            let invalid = [
                Block { rows: 1, heads: 2, width: 4, position: 0, family: 0 },
                Block { rows: 2, heads: 2, width: 4, position: 0, family: 0 },
            ];
            assert!(Statement { blocks: &invalid, ..s }.required().is_err());
        }
    }
}

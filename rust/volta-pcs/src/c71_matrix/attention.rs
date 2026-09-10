//! Raw attention reductions on the declared eager rectangles. Original
//! Q/K/V/probability endpoints still require SAME-source and KV-history links.

use super::*;

pub(super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub layer: u8,
    pub old: usize,
    pub prompt: usize,
    pub tokens: usize,
    pub groups: usize,
    pub repeats: usize,
    pub lanes: usize,
}

pub(super) struct QkProof {
    raw: Fp3,
    reduction: p0::Proof,
    product: [Fp3; 2],
}

pub(super) struct QkPending<T> {
    pub raw_point: Vec<Fp3>, // group || repeat || query || key
    pub q_point: Vec<Fp3>,   // query || group || repeat || lane
    pub k_point: Vec<Fp3>,   // key || group || lane
    pub originals: [T; 3],   // raw, Q, K
}

pub(super) struct PvProof {
    raw: Fp3,
    reduction: p0::Proof,
    product: [Fp3; 2],
    link: Vec<[Fp3; 4]>,
    terminal: [Fp3; 2],
}

pub(super) struct PvPending<T> {
    pub raw_point: Vec<Fp3>, // query || group || repeat || lane
    pub pi_point: Vec<Fp3>,  // group || repeat || query || key (link endpoint)
    pub v_point: Vec<Fp3>,   // key || group || lane (product endpoint)
    pub originals: [T; 3],   // raw, Pi, V; M is discharged by the link
}

impl Statement<'_> {
    fn dimensions(&self) -> Result<[usize; 5], String> {
        if self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
            || self.layer >= 60
            || self.tokens == 0
            || self.tokens > 150
            || self.prompt == 0
            || self.prompt > self.tokens
            || self.old > 4096 - self.tokens
            || !self.groups.is_power_of_two()
            || self.groups > 32
            || !self.repeats.is_power_of_two()
            || self.repeats > 32
            || self.groups * self.repeats > 32
            || !self.lanes.is_power_of_two()
            || self.lanes > 512
        {
            return Err("attention public shape, context or GQA profile differs".into());
        }
        let b = [self.tokens, self.old + self.tokens, self.groups, self.repeats, self.lanes]
            .map(|n| n.next_power_of_two().ilog2() as usize);
        if b[0] + b[1] + b[2] + b[4] > 15 {
            return Err("attention QK exceeds native D15".into());
        }
        Ok(b)
    }

    fn keys_at(&self, i: usize) -> usize {
        if i >= self.tokens {
            0
        } else if i < self.prompt {
            self.old + self.prompt
        } else {
            self.old + i + 1
        }
    }

    pub fn qk_required(&self) -> Result<usize, String> {
        let [t, k, g, _, a] = self.dimensions()?;
        Ok(2 + p0::required(t + k + g + a, true))
    }

    pub fn pv_required(&self) -> Result<usize, String> {
        let [t, k, g, _, _] = self.dimensions()?;
        Ok(3 + p0::required(g + k, true) + 3 * (t + k))
    }

    fn bind(&self, kind: u8, fs: &mut Fs) {
        let mut bytes = b"C71-attention-B12-v1;eager-rectangle;GQA-quotient;MSB\0".to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        bytes.extend([self.layer, kind]);
        for n in [self.old, self.prompt, self.tokens, self.groups, self.repeats, self.lanes] {
            bytes.extend((n as u64).to_le_bytes());
        }
        fs.set_phase(0x1200 + u16::from(kind));
        fs.record(0xf0, &bytes);
    }

    // MLE of EQ(ri,i)*EQ(rj,j)*L(i,j), formed on BOOLEAN vertices.
    // ponytail: direct public O(T*N) evaluation; use the existing carry DP
    // if this public verifier work matters for larger admitted contexts.
    fn rectangle_at(&self, ri: &[Fp3], rj: &[Fp3], ui: &[Fp3], uj: &[Fp3]) -> Fp3 {
        let (ri, rj, ui, uj) = (eq(ri), eq(rj), eq(ui), eq(uj));
        (0..self.tokens).fold(Fp3::ZERO, |v, i| {
            v + ri[i] * ui[i] * (0..self.keys_at(i)).fold(Fp3::ZERO, |v, j| v + rj[j] * uj[j])
        })
    }
}

pub(super) fn prove_qk(
    s: &Statement<'_>,
    raw: impl Fn(usize, usize, usize) -> [u8; 6],
    query: impl Fn(usize, usize, usize) -> i16,
    key: impl Fn(usize, usize, usize) -> i16,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(QkProof, QkPending<Auth>), String> {
    let [t, k, g, e, a] = s.dimensions()?;
    let count = s.qk_required()?;
    if correlations.len() < count {
        return Err("attention QK prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    s.bind(0, fs);
    let raw_point: Vec<_> = (0..g + e + t + k).map(|_| fs.fp3()).collect();
    let (rb, re, ri, rj) = (
        &raw_point[..g],
        &raw_point[g..g + e],
        &raw_point[g + e..g + e + t],
        &raw_point[g + e + t..],
    );
    let (head, wi, wj, wb, we) = (eq(&raw_point[..g + e]), eq(ri), eq(rj), eq(rb), eq(re));
    let mut value = Fp3::ZERO;
    for h in 0..s.groups * s.repeats {
        for i in 0..1 << t {
            for j in 0..s.old + s.tokens {
                // Raw source includes padded QUERY rows. Read them too: the linear
                // relation must prove those field values zero, not presume it.
                let word = raw(h, i, j)
                    .iter()
                    .enumerate()
                    .fold(0i64, |v, (b, &u)| v + (i64::from(u) << (8 * b)));
                value += head[h] * wi[i] * wj[j] * signed(word - (1 << 47));
            }
        }
    }
    let (wire, original) = range::authenticate([value], &mut rows);
    record_values(fs, 0xf1, &wire);
    let size = 1 << (t + k + g + a);
    let (mut q, mut kv, mut public) =
        (vec![Fp3::ZERO; size], vec![Fp3::ZERO; size], vec![Fp3::ZERO; size]);
    // Dense bounded seam; the large domain's streaming schedule is separate.
    for i in 0..1 << t {
        for j in 0..1 << k {
            for b in 0..s.groups {
                for lane in 0..s.lanes {
                    let index = (((i << k) + j) * s.groups + b) * s.lanes + lane;
                    if i < s.tokens {
                        q[index] = (0..s.repeats).fold(Fp3::ZERO, |v, e| {
                            v + we[e] * signed(i64::from(query(i, b * s.repeats + e, lane)))
                        });
                    }
                    if j < s.old + s.tokens {
                        kv[index] = signed(i64::from(key(j, b, lane)));
                    }
                    if j < s.keys_at(i) {
                        public[index] = wi[i] * wj[j] * wb[b];
                    }
                }
            }
        }
    }
    let (reduction, point, inputs) = p0::prove_public(q, kv, original[0], public, fs, &mut rows)?;
    let product = range::prove_products(&[inputs], rows.next().unwrap(), fs);
    let (ui, uj, ub, ua) =
        (&point[..t], &point[t..t + k], &point[t + k..t + k + g], &point[t + k + g..]);
    let q_point = [ui, ub, re, ua].concat();
    let k_point = [uj, ub, ua].concat();
    debug_assert!(rows.next().is_none());
    Ok((
        QkProof { raw: wire[0], reduction, product },
        QkPending { raw_point, q_point, k_point, originals: [original[0], inputs[0], inputs[1]] },
    ))
}

pub(super) fn verify_qk(
    s: &Statement<'_>,
    proof: &QkProof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<QkPending<Key>, String> {
    let [t, k, g, e, a] = s.dimensions()?;
    let count = s.qk_required()?;
    if correlations.len() < count {
        return Err("attention QK verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    s.bind(0, fs);
    let raw_point: Vec<_> = (0..g + e + t + k).map(|_| fs.fp3()).collect();
    let (rb, re, ri, rj) = (
        &raw_point[..g],
        &raw_point[g..g + e],
        &raw_point[g + e..g + e + t],
        &raw_point[g + e + t..],
    );
    let raw = range::correct([proof.raw], delta, &mut rows)[0];
    record_values(fs, 0xf1, &[proof.raw]);
    let (point, inputs) = p0::verify_public(
        t + k + g + a,
        raw,
        &proof.reduction,
        delta,
        |u| {
            let group = rb
                .iter()
                .zip(&u[t + k..t + k + g])
                .fold(Fp3::ONE, |v, (&r, &u)| v * ((Fp3::ONE - r) * (Fp3::ONE - u) + r * u));
            group * s.rectangle_at(ri, rj, &u[..t], &u[t..t + k])
        },
        fs,
        &mut rows,
    )?;
    range::verify_products(&[inputs], rows.next().unwrap(), proof.product, delta, fs)?;
    let (ui, uj, ub, ua) =
        (&point[..t], &point[t..t + k], &point[t + k..t + k + g], &point[t + k + g..]);
    let q_point = [ui, ub, re, ua].concat();
    let k_point = [uj, ub, ua].concat();
    debug_assert!(rows.next().is_none());
    Ok(QkPending { raw_point, q_point, k_point, originals: [raw, inputs[0], inputs[1]] })
}

pub(super) fn prove_pv(
    s: &Statement<'_>,
    raw: impl Fn(usize, usize, usize) -> [u8; 6],
    probability: impl Fn(usize, usize, usize) -> i16,
    value: impl Fn(usize, usize, usize) -> i16,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(PvProof, PvPending<Auth>), String> {
    let [t, k, g, e, a] = s.dimensions()?;
    let count = s.pv_required()?;
    if correlations.len() < count {
        return Err("attention PV prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    s.bind(1, fs);
    let raw_point: Vec<_> = (0..t + g + e + a).map(|_| fs.fp3()).collect();
    let (ri, rb, re, ra) = (
        &raw_point[..t],
        &raw_point[t..t + g],
        &raw_point[t + g..t + g + e],
        &raw_point[t + g + e..],
    );
    let (wi, wb, we, wa) = (eq(ri), eq(rb), eq(re), eq(ra));
    let head = eq(&raw_point[t..t + g + e]);
    let mut y = Fp3::ZERO;
    for i in 0..s.tokens {
        for h in 0..s.groups * s.repeats {
            for a in 0..s.lanes {
                let word = raw(i, h, a)
                    .iter()
                    .enumerate()
                    .fold(0i64, |v, (b, &u)| v + (i64::from(u) << (8 * b)));
                y += wi[i] * head[h] * wa[a] * signed(word - (1 << 47));
            }
        }
    }
    let (wire, original) = range::authenticate([y], &mut rows);
    record_values(fs, 0xf2, &wire);
    let size = 1 << (g + k);
    let (mut m, mut v, mut public) =
        (vec![Fp3::ZERO; size], vec![Fp3::ZERO; size], vec![Fp3::ZERO; size]);
    for b in 0..s.groups {
        for j in 0..1 << k {
            let index = (b << k) + j;
            public[index] = wb[b];
            if j >= s.old + s.tokens {
                continue;
            }
            v[index] =
                (0..s.lanes).fold(Fp3::ZERO, |v, a| v + wa[a] * signed(i64::from(value(j, b, a))));
            for i in 0..s.tokens {
                if j < s.keys_at(i) {
                    for e in 0..s.repeats {
                        m[index] +=
                            wi[i] * we[e] * signed(i64::from(probability(b * s.repeats + e, i, j)));
                    }
                }
            }
        }
    }
    let (reduction, u, inputs) = p0::prove_public(m, v, original[0], public, fs, &mut rows)?;
    let product = range::prove_products(&[inputs], rows.next().unwrap(), fs);
    let (ub, uj) = (&u[..g], &u[g..]);
    let (whead, wj) = (eq(&[ub, re].concat()), eq(uj));
    let (mut pi, mut f) = (vec![Fp3::ZERO; 1 << (t + k)], vec![Fp3::ZERO; 1 << (t + k)]);
    for i in 0..s.tokens {
        for j in 0..s.old + s.tokens {
            let index = (i << k) + j;
            pi[index] = (0..s.groups * s.repeats)
                .fold(Fp3::ZERO, |v, h| v + whead[h] * signed(i64::from(probability(h, i, j))));
            if j < s.keys_at(i) {
                f[index] = wi[i] * wj[j];
            }
        }
    }
    // M was authenticated BEFORE this independent probability link. This is
    // MLE(L*Pi), not the invalid product MLE(L)*MLE(Pi) at a field key.
    fs.set_phase(0x1202);
    fs.record(0xf3, b"PV/original-M-to-Pi;token-key;public-rectangle-v1");
    let (link, point, target, pi, f) = prove_product(pi, f, inputs[0], fs, &mut rows);
    let (correction, pi) = range::authenticate([pi], &mut rows);
    let terminal = [correction[0], target.m - f * pi[0].m];
    fs.set_phase(0x1203);
    record_values(fs, 0xf4, &terminal);
    let pi_point = [ub, re, &point[..t], &point[t..]].concat();
    let v_point = [uj, ub, ra].concat();
    debug_assert!(rows.next().is_none());
    Ok((
        PvProof { raw: wire[0], reduction, product, link, terminal },
        PvPending { raw_point, pi_point, v_point, originals: [original[0], pi[0], inputs[1]] },
    ))
}

pub(super) fn verify_pv(
    s: &Statement<'_>,
    proof: &PvProof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<PvPending<Key>, String> {
    let [t, k, g, e, a] = s.dimensions()?;
    let count = s.pv_required()?;
    if correlations.len() < count || proof.link.len() != t + k {
        return Err("attention PV proof shape or capacity differs".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    s.bind(1, fs);
    let raw_point: Vec<_> = (0..t + g + e + a).map(|_| fs.fp3()).collect();
    let (ri, rb, re, ra) = (
        &raw_point[..t],
        &raw_point[t..t + g],
        &raw_point[t + g..t + g + e],
        &raw_point[t + g + e..],
    );
    let raw = range::correct([proof.raw], delta, &mut rows)[0];
    record_values(fs, 0xf2, &[proof.raw]);
    let (u, inputs) = p0::verify_public(
        g + k,
        raw,
        &proof.reduction,
        delta,
        |u| {
            rb.iter()
                .zip(&u[..g])
                .fold(Fp3::ONE, |v, (&r, &u)| v * ((Fp3::ONE - r) * (Fp3::ONE - u) + r * u))
        },
        fs,
        &mut rows,
    )?;
    range::verify_products(&[inputs], rows.next().unwrap(), proof.product, delta, fs)?;
    let (ub, uj) = (&u[..g], &u[g..]);
    fs.set_phase(0x1202);
    fs.record(0xf3, b"PV/original-M-to-Pi;token-key;public-rectangle-v1");
    let (target, point) = verify_product(&proof.link, inputs[0], delta, fs, &mut rows)
        .map_err(|e| format!("attention PV probability link: {e}"))?;
    let pi = range::correct([proof.terminal[0]], delta, &mut rows)[0];
    if target.k - s.rectangle_at(ri, uj, &point[..t], &point[t..]) * pi.k != proof.terminal[1] {
        return Err("attention PV original Pi endpoint MAC rejected".into());
    }
    fs.set_phase(0x1203);
    record_values(fs, 0xf4, &proof.terminal);
    let pi_point = [ub, re, &point[..t], &point[t..]].concat();
    let v_point = [uj, ub, ra].concat();
    debug_assert!(rows.next().is_none());
    Ok(PvPending { raw_point, pi_point, v_point, originals: [raw, pi, inputs[1]] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::RngExt;

    fn word_form(offset: usize, p: &[Fp3], width: usize, live: Fp3) -> (Vec<Cube>, Fp3) {
        let lanes = width.next_power_of_two().ilog2() as usize;
        (
            (0..width)
                .map(|b| {
                    let mut point = p.to_vec();
                    point.extend((0..lanes).rev().map(|j| {
                        if b >> j & 1 == 1 {
                            Fp3::ONE
                        } else {
                            Fp3::ZERO
                        }
                    }));
                    Cube { offset, point, coefficient: signed(1 << (8 * b)) }
                })
                .collect(),
            live * signed(1 << (8 * width - 1)),
        )
    }

    #[test]
    fn c71_b12_attention_pv_original_probability_link_and_v_close_same_ranged_source() {
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = [84; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(39);
        let honest_pi: Vec<i16> =
            (0..64).map(|i| if i / 4 % 4 == 3 { 0 } else { (i % 7) as i16 - 3 }).collect();
        let honest_v: Vec<i16> = (0..16).map(|i| (i % 5) as i16 - 2).collect();
        let raw = |pi: &[i16], v: &[i16]| -> Vec<i64> {
            (0..24)
                .map(|index| {
                    let (i, h, a) = (index / 8, index % 8 / 2, index % 2);
                    (0..if i < 2 { 3 } else { 4 })
                        .map(|j| {
                            i64::from(pi[(h * 4 + i) * 4 + j])
                                * i64::from(v[(j * 2 + h / 2) * 2 + a])
                        })
                        .sum()
                })
                .collect()
        };
        let source = |raw: &[i64]| {
            let mut bytes = vec![0; 1024];
            for (i, &x) in raw.iter().enumerate() {
                let x = (x + (1 << 47)) as u64;
                for b in 0..6 {
                    bytes[8 * i + b] = ((x >> (8 * b)) & 255) as i16;
                }
            }
            for (offset, words) in [(256, &honest_pi), (384, &honest_v)] {
                for (i, &x) in words.iter().enumerate() {
                    let x = i32::from(x) + 32768;
                    bytes[offset + 2 * i] = (x & 255) as i16;
                    bytes[offset + 2 * i + 1] = (x >> 8) as i16;
                }
            }
            bytes
        };
        let forms = |p: &PvPending<_>| {
            [
                word_form(0, &p.raw_point, 6, byte_function::live_mass(3, &p.raw_point[..2])),
                word_form(256, &p.pi_point, 2, Fp3::ONE),
                word_form(384, &p.v_point, 2, Fp3::ONE),
            ]
        };
        for fault in 0..5 {
            let (mut pi, mut v) = (honest_pi.clone(), honest_v.clone());
            if fault == 2 || fault == 4 {
                pi[0] += 1;
            }
            if fault == 3 {
                v[0] += 1;
            }
            let mut raw = raw(&pi, &v);
            if fault == 1 {
                raw[0] += 1;
            }
            let model = Model::new(32, source(&raw)).unwrap();
            let s = Statement {
                root: &model.root,
                profile: &profile,
                view: layout,
                attempt,
                layer: 0,
                old: 1,
                prompt: 2,
                tokens: 3,
                groups: 2,
                repeats: 2,
                lanes: 2,
            };
            assert_eq!(s.pv_required().unwrap(), 30);
            let mut rng = MatrixRng::from_seed([110 + fault; 32]);
            let rows: Vec<Auth> = (0..572)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"raw PV original contracted probability link", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            // Only fault 4 supplies a different Pi to the first contraction.
            // The second scan uses committed Pi: its ORIGINAL M must reject.
            let reads = std::cell::Cell::new(0usize);
            let (proof, p) = prove_pv(
                &s,
                |i, h, a| {
                    let x = (raw[(i * 4 + h) * 2 + a] + (1 << 47)) as u64;
                    std::array::from_fn(|b| (x >> (8 * b)) as u8)
                },
                |h, i, j| {
                    let n = reads.get();
                    reads.set(n + 1);
                    let p = if fault == 4 && n >= 40 { &honest_pi } else { &pi };
                    p[(h * 4 + i) * 4 + j]
                },
                |j, b, a| v[(j * 2 + b) * 2 + a],
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(fs.requests(), 13);
            assert_ne!(&p.pi_point[4..], &p.v_point[..2]);
            let (range_proof, ranged, targets) = range::prove(
                &model,
                attempt,
                layout,
                416,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let pf = forms(&p);
            let all_forms: Vec<_> =
                ranged.into_iter().chain(pf.iter().map(|(f, _)| f.clone())).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(p.originals.into_iter().zip(&pf).map(|(a, (_, b))| Auth::new(a.x + *b, a.m)))
                .collect();
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &all_forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let result = verify_pv(&s, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 || fault == 4 {
                let error = result.err().expect("wrong raw or detached M passed PV");
                if fault == 4 {
                    assert!(error.contains("PV probability link"), "{error}");
                }
                continue;
            }
            let p = result.unwrap();
            assert_eq!(fs.requests(), 13);
            let (ranged, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                416,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let vf = [
                word_form(0, &p.raw_point, 6, byte_function::live_mass(3, &p.raw_point[..2])),
                word_form(256, &p.pi_point, 2, Fp3::ONE),
                word_form(384, &p.v_point, 2, Fp3::ONE),
            ];
            let all_forms: Vec<_> =
                ranged.into_iter().chain(vf.iter().map(|(f, _)| f.clone())).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(
                    p.originals
                        .into_iter()
                        .zip(&vf)
                        .map(|(k, (_, b))| Key::new(k.k + delta * (*b))),
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
            if fault == 2 || fault == 3 {
                assert!(result.is_err(), "changed Pi/V with consistent raw detached from A");
            } else {
                assert_eq!(result.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
            let mut exhausted = vec![Auth::ZERO; 29].into_iter();
            assert!(prove_pv(
                &s,
                |_, _, _| panic!("read raw on exhaustion"),
                |_, _, _| panic!("read Pi on exhaustion"),
                |_, _, _| panic!("read V on exhaustion"),
                &mut start(),
                &mut exhausted,
            )
            .is_err());
            assert_eq!(exhausted.len(), 29);
        }
    }

    #[test]
    fn c71_b12_attention_qk_rectangle_gqa_and_original_q_k_raw_share_ranged_source() {
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = [83; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(37);
        let q: Vec<i16> = (0..24).map(|i| (i % 5) as i16 - 2).collect();
        let honest_k: Vec<i16> = (0..16).map(|i| (i % 7) as i16 - 3).collect();
        let score = |k: &[i16], wrong_gqa: bool| -> Vec<i64> {
            (0..64)
                .map(|index| {
                    let (h, i, j) = (index / 16, (index % 16) / 4, index % 4);
                    let limit = if i >= 3 {
                        0
                    } else if i < 2 {
                        3
                    } else {
                        4
                    };
                    if j >= limit {
                        return 0;
                    }
                    let b = if wrong_gqa { h % 2 } else { h / 2 };
                    (0..2)
                        .map(|a| {
                            i64::from(q[(i * 4 + h) * 2 + a]) * i64::from(k[(j * 2 + b) * 2 + a])
                        })
                        .sum()
                })
                .collect()
        };
        let source = |raw: &[i64], k: &[i16]| {
            let mut source = vec![0i16; 1024];
            for (i, &v) in raw.iter().enumerate() {
                let v = (v + (1 << 47)) as u64;
                for b in 0..6 {
                    source[8 * i + b] = i16::from((v >> (8 * b)) as u8);
                }
            }
            for (offset, words) in [(512, q.as_slice()), (576, k)] {
                for (i, &v) in words.iter().enumerate() {
                    let v = (i32::from(v) + 32768) as u16;
                    for b in 0..2 {
                        source[offset + 2 * i + b] = i16::from((v >> (8 * b)) as u8);
                    }
                }
            }
            source
        };
        for fault in 0..5 {
            let mut k = honest_k.clone();
            if fault == 2 {
                k[0] += 1;
            }
            let mut raw = score(&k, fault == 3);
            if fault == 1 {
                raw[0] += 1;
            }
            if fault == 4 {
                raw[12] = 1;
            } // query padding is a SOURCE value, not assumed zero
            let model = Model::new(
                32,
                if fault == 2 {
                    source(&score(&honest_k, false), &honest_k)
                } else {
                    source(&raw, &k)
                },
            )
            .unwrap();
            let s = Statement {
                root: &model.root,
                profile: &profile,
                view: layout,
                attempt,
                layer: 0,
                old: 1,
                prompt: 2,
                tokens: 3,
                groups: 2,
                repeats: 2,
                lanes: 2,
            };
            assert_eq!(s.keys_at(0), 3); // future PROMPT key is included before causal mask
            assert_eq!(s.keys_at(2), 4);
            assert_eq!(s.keys_at(3), 0);
            let count = s.qk_required().unwrap() + 510 + 32;
            assert_eq!(count, 571);
            let mut rng = MatrixRng::from_seed([167; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"raw QK GQA rectangles with original source MACs", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (proof, p) = prove_qk(
                &s,
                |h, i, j| {
                    let v = (raw[(h * 4 + i) * 4 + j] + (1 << 47)) as u64;
                    std::array::from_fn(|b| (v >> (8 * b)) as u8)
                },
                |i, h, a| q[(i * 4 + h) * 2 + a],
                |j, b, a| k[(j * 2 + b) * 2 + a],
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(fs.requests(), 13);
            let (range_proof, ranged, targets) = range::prove(
                &model,
                attempt,
                layout,
                608,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let forms = [
                word_form(0, &p.raw_point, 6, Fp3::ONE),
                word_form(512, &p.q_point, 2, byte_function::live_mass(3, &p.q_point[..2])),
                word_form(576, &p.k_point, 2, Fp3::ONE),
            ];
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
            let result = verify_qk(&s, &proof, delta, &mut fs, &mut vrows);
            if [1, 3, 4].contains(&fault) {
                assert!(result.is_err(), "wrong raw/GQA/query padding passed QK");
                continue;
            }
            let p = result.unwrap();
            assert_eq!(fs.requests(), 13);
            let (ranged, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                608,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let forms = [
                word_form(0, &p.raw_point, 6, Fp3::ONE),
                word_form(512, &p.q_point, 2, byte_function::live_mass(3, &p.q_point[..2])),
                word_form(576, &p.k_point, 2, Fp3::ONE),
            ];
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
                assert!(result.is_err(), "changed K and consistent raw detached from A");
            } else {
                assert_eq!(result.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
            let mut exhausted = vec![Auth::ZERO; s.qk_required().unwrap() - 1].into_iter();
            let before = exhausted.len();
            assert!(prove_qk(
                &s,
                |_, _, _| panic!("read raw on exhaustion"),
                |_, _, _| panic!("read Q on exhaustion"),
                |_, _, _| panic!("read K on exhaustion"),
                &mut start(),
                &mut exhausted
            )
            .is_err());
            assert_eq!(exhausted.len(), before);
            assert!(Statement { repeats: 3, ..s }.qk_required().is_err());
        }
    }
}

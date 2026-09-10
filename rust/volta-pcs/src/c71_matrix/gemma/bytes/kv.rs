//! Split original KV endpoint MACs over immutable accepted A tails and the
//! current A. Prior roots/receipts must come from the FULL verifier's ledger.
//! This component neither proves those earlier Gemma executions nor promotes
//! a new receipt; each returned target still needs its source PCS.

use super::*;
use crate::c71_matrix::gemma::rms::prefix;
use crate::c71_matrix::{
    range, record_values, signed, AttemptContext, Auth, C61Commitment, Fs, Key,
};

impl Bytes {
    /// Local token t contributes at global offset+t. Dyadic pieces must
    /// align in BOTH domains: no reading physical tail as old padding.
    pub fn kv_segment_form(
        &self,
        source: usize,
        offset: usize,
        total: usize,
        row: &[Fp3],
        column: &[Fp3],
        coefficient: Fp3,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        let s = self.scalar.layout.sources.get(source).ok_or("KV segment source missing")?;
        if self.widths[source] != 2
            || total == 0
            || total > 4096
            || row.len() != bits(total)
            || column.len() != bits(s.cols)
            || !s.cols.is_power_of_two()
            || offset.checked_add(s.rows).is_none_or(|end| end > total)
        {
            return Err("KV segment source codec, axes or offset differs".into());
        }
        let (mut local, mut form, mut bias) = (0, Vec::new(), Fp3::ZERO);
        while local < s.rows {
            let mut size = (s.rows - local).next_power_of_two();
            while size > s.rows - local || local % size != 0 || (offset + local) % size != 0 {
                size /= 2;
            }
            let low = bits(size);
            let weight = coefficient * eq_index(&row[..row.len() - low], (offset + local) / size);
            let point = prefix(local, size, s.rows, &row[row.len() - low..]);
            let (f, b) = self.word_form(source, &point, column, weight)?;
            form.extend(f);
            bias += b;
            local += size;
        }
        Ok((form, bias))
    }
}

pub(in crate::c71_matrix) struct Segment<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub bytes: &'a Bytes,
    pub model: [u8; 32],
    pub quantization: [u8; 32],
    pub tokens: usize,
    pub receipt: [u8; 32], // verified prior full-certificate digest; zero for current
}

pub(in crate::c71_matrix) struct Request<T> {
    pub source: usize,   // canonical k_rope/v_norm ID, preserved across A layouts
    pub point: Vec<Fp3>, // combined key || group || lane, MSB first
    pub original: T,     // already emitted ORIGINAL QK/PV endpoint MAC
}

pub(in crate::c71_matrix) struct Statement<'a> {
    pub model: [u8; 32],
    pub quantization: [u8; 32],
    pub attempt: AttemptContext,
    pub segments: &'a [Segment<'a>], // prior accepted roots, then current
}

pub(in crate::c71_matrix) struct Proof {
    old: Vec<Fp3>,
}

pub(in crate::c71_matrix) struct Opening<T> {
    pub form: Vec<Cube>,
    pub original: T, // encoded-byte target, with its public bias already added
}

impl Statement<'_> {
    fn shape<T>(&self, requests: &[Request<T>]) -> Result<usize, String> {
        if self.model == [0; 32]
            || self.quantization == [0; 32]
            || !self.attempt.valid()
            || self.segments.is_empty()
            || self.segments.len() > 3
            || self.attempt.slot as usize + 1 != self.segments.len()
            || requests.is_empty()
            || requests.len() > 128
        {
            return Err("KV original endpoint or fixed-run source count differs".into());
        }
        let expected = self.segments.iter().rev().nth(1).map_or([0; 32], |s| s.receipt);
        if self.attempt.predecessor != expected {
            return Err("KV accepted predecessor differs".into());
        }
        let mut roots = std::collections::BTreeSet::new();
        let mut total = 0;
        let first = &self.segments[0];
        for (i, s) in self.segments.iter().enumerate() {
            if s.root.num_roots() != 1
                || s.profile.is_empty()
                || s.model != self.model
                || s.quantization != self.quantization
                || s.tokens == 0
                || s.tokens > 150
                || !roots.insert(s.root.roots()[0])
                || (s.receipt == [0; 32]) != (i + 1 == self.segments.len())
                || s.bytes.scalar.weight_layout != first.bytes.scalar.weight_layout
            {
                return Err("KV accepted source identity, receipt or one-time root differs".into());
            }
            total += s.tokens;
            for r in requests {
                let src = s
                    .bytes
                    .scalar
                    .layout
                    .sources
                    .get(r.source)
                    .ok_or("KV canonical source missing")?;
                let original = first
                    .bytes
                    .scalar
                    .layout
                    .sources
                    .get(r.source)
                    .ok_or("KV original source missing")?;
                if s.bytes.widths[r.source] != 2
                    || src.rows != s.tokens
                    || !src.cols.is_power_of_two()
                    || src.name != original.name
                    || src.cols != original.cols
                {
                    return Err("KV current/prior canonical tail route differs".into());
                }
            }
        }
        if total > 4096
            || requests.iter().any(|r| {
                r.point.len()
                    != bits(total) + bits(first.bytes.scalar.layout.sources[r.source].cols)
            })
        {
            return Err("KV original combined endpoint arity differs".into());
        }
        Ok(total)
    }

    fn forms<T>(
        &self,
        requests: &[Request<T>],
        fs: &mut Fs,
    ) -> Result<(Vec<(Vec<Cube>, Fp3)>, Vec<Fp3>), String> {
        let total = self.shape(requests)?;
        let mut frame =
            b"C71-KV-A-tails-B12-v1;original-KV-MACs;current-key;accepted-prefix\0".to_vec();
        frame.extend(self.model);
        frame.extend(self.quantization);
        frame.extend(self.attempt.encode());
        frame.extend((self.segments.len() as u64).to_le_bytes());
        for s in self.segments {
            frame.extend(s.root.roots()[0]);
            frame.extend(s.bytes.layout_digest);
            frame.extend((s.profile.len() as u64).to_le_bytes());
            frame.extend(s.profile);
            frame.extend((s.tokens as u64).to_le_bytes());
            frame.extend(s.receipt);
        }
        frame.extend((requests.len() as u64).to_le_bytes());
        for r in requests {
            frame.extend((r.source as u64).to_le_bytes());
            frame.extend((r.point.len() as u64).to_le_bytes());
            for v in &r.point {
                frame.extend(v.to_bytes());
            }
        }
        fs.set_phase(0x1400);
        fs.record(0xfb, &frame);
        let lambda = fs.fp3();
        let mut power = Fp3::ONE;
        let coefficients: Vec<_> = requests
            .iter()
            .map(|_| {
                let p = power;
                power = power * lambda;
                p
            })
            .collect();
        let (mut result, mut offset) = (Vec::new(), 0);
        for s in self.segments {
            let (mut form, mut bias) = (Vec::new(), Fp3::ZERO);
            for (r, &c) in requests.iter().zip(&coefficients) {
                let (f, b) = s.bytes.kv_segment_form(
                    r.source,
                    offset,
                    total,
                    &r.point[..bits(total)],
                    &r.point[bits(total)..],
                    c,
                )?;
                form.extend(f);
                bias += b;
            }
            if form.len() > crate::c71_matrix::linear::MAX_CUBES {
                return Err("KV source form exceeds cube cap".into());
            }
            result.push((form, bias));
            offset += s.tokens;
        }
        Ok((result, coefficients))
    }
}

pub(in crate::c71_matrix) fn prove(
    s: &Statement<'_>,
    requests: &[Request<Auth>],
    read: impl Fn(usize, usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Opening<Auth>>), String> {
    s.shape(requests)?;
    let count = s.segments.len() - 1;
    if correlations.len() < count || s.segments.iter().any(|s| bits(s.bytes.live) > 34) {
        return Err("KV source exceeds D34 or prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (forms, coefficients) = s.forms(requests, fs)?;
    let mut current =
        requests.iter().zip(coefficients).fold(Auth::ZERO, |v, (r, c)| v.add(r.original.scale(c)));
    let (mut old, mut result) = (Vec::new(), Vec::new());
    for (i, (form, bias)) in forms.into_iter().enumerate() {
        if i == count {
            result.push(Opening { form, original: Auth::new(current.x + bias, current.m) });
        } else {
            let encoded = form.iter().fold(Fp3::ZERO, |v, c| {
                let at = crate::c71_matrix::eq(&c.point)
                    .into_iter()
                    .enumerate()
                    .fold(Fp3::ZERO, |v, (j, w)| v + w * signed(i64::from(read(i, c.offset + j))));
                v + c.coefficient * at
            });
            let value = encoded - bias;
            let (wire, a) = range::authenticate([value], &mut rows);
            current = current.add(a[0].scale(Fp3::ZERO - Fp3::ONE));
            old.push(wire[0]);
            result.push(Opening { form, original: Auth::new(a[0].x + bias, a[0].m) });
        }
    }
    fs.set_phase(0x1401);
    record_values(fs, 0xfc, &old);
    debug_assert!(rows.next().is_none());
    Ok((Proof { old }, result))
}

pub(in crate::c71_matrix) fn verify(
    s: &Statement<'_>,
    requests: &[Request<Key>],
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<Vec<Opening<Key>>, String> {
    s.shape(requests)?;
    let count = s.segments.len() - 1;
    if proof.old.len() != count
        || correlations.len() < count
        || s.segments.iter().any(|s| bits(s.bytes.live) > 34)
    {
        return Err("KV native source/proof shape or verifier capacity differs".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (forms, coefficients) = s.forms(requests, fs)?;
    let mut current =
        requests.iter().zip(coefficients).fold(Key::ZERO, |v, (r, c)| v.add(r.original.scale(c)));
    let mut result = Vec::new();
    for (i, (form, bias)) in forms.into_iter().enumerate() {
        if i == count {
            result.push(Opening { form, original: Key::new(current.k + delta * bias) });
        } else {
            let key = range::correct([proof.old[i]], delta, &mut rows)[0];
            current = current.add(key.scale(Fp3::ZERO - Fp3::ONE));
            result.push(Opening { form, original: Key::new(key.k + delta * bias) });
        }
    }
    fs.set_phase(0x1401);
    record_values(fs, 0xfc, &proof.old);
    debug_assert!(rows.next().is_none());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{from_p3, gamma, linear, matrix_config, MatrixRng, Model, E};
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_kv_original_macs_split_across_three_ranged_roots_with_fresh_rows() {
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let first = bytes.scalar.layout.sources.len();
        let bytes =
            bytes.append(vec![("test/K".into(), 3, 2, 2), ("test/V".into(), 3, 2, 2)]).unwrap();
        assert!(bytes.live <= 1024);
        let value = |segment: usize, source: usize, t: usize, c: usize| {
            if source == first {
                3 * segment as i64 + 2 * t as i64 - c as i64 - 4
            } else if source == first + 1 {
                2 * segment as i64 - t as i64 + 3 * c as i64 - 2
            } else {
                0
            }
        };
        let new_models = || {
            (0..3)
                .map(|segment| {
                    let mut packed = vec![0u8; bytes.live];
                    for (id, s) in bytes.scalar.layout.sources.iter().enumerate() {
                        for row in 0..s.rows {
                            for col in 0..s.cols {
                                for b in 0..bytes.widths[id] {
                                    packed[bytes.packed_offsets[id]
                                        + (row * s.cols + col) * bytes.widths[id]
                                        + b] =
                                        (value(segment, id, row, col) as u64 >> (8 * b)) as u8;
                                }
                            }
                        }
                    }
                    Model::new(
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
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let alter = (0..1024)
            .find(|&i| {
                bytes
                    .virtual_to_packed(i)
                    .unwrap()
                    .is_some_and(|(a, _)| a == bytes.packed_offsets[first])
            })
            .unwrap();
        let profile = gamma(&matrix_config(32).unwrap());
        let delta = signed(43);
        for fault in 0..3 {
            // Independent fixtures: no A root exceeds three exposures
            // when testing different adversarial runs.
            let models = new_models();
            // These receipts certify this component's byte/PCS history,
            // not complete Gemma inference. Full acceptance is still external.
            let mut receipts: Vec<[u8; 32]> = Vec::new();
            let mut rejected = false;
            for step in 0..3 {
                let attempt = AttemptContext {
                    session: [1; 32],
                    capacity: [2; 32],
                    slot: step as u8,
                    predecessor: receipts.last().copied().unwrap_or([0; 32]),
                    nonce: [3 + step as u8; 32],
                };
                let segments: Vec<_> = (0..=step)
                    .map(|i| Segment {
                        root: &models[i].root,
                        profile: &profile,
                        bytes: &bytes,
                        model: [7; 32],
                        quantization: [8; 32],
                        tokens: 3,
                        receipt: if i == step { [0; 32] } else { receipts[i] },
                    })
                    .collect();
                let s = Statement {
                    model: [7; 32],
                    quantization: [8; 32],
                    attempt,
                    segments: &segments,
                };
                let total = 3 * (step + 1);
                let key_bits = bits(total);
                let start = || {
                    let mut fs =
                        Fs::new(b"original KV source tail routing; component history", 100000);
                    let mut frame = attempt.encode();
                    for src in &segments {
                        frame.extend(src.root.roots()[0]);
                        frame.extend(src.receipt);
                    }
                    fs.record(0xfd, &frame);
                    fs
                };
                let count = 2 + step + 510 + 32 * (step + 1);
                assert_eq!(count, [544, 577, 610][step]);
                let mut rng = MatrixRng::from_seed([150 + 3 * fault + step as u8; 32]);
                let rows: Vec<_> = (0..count)
                    .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                    .collect();
                let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
                let mut fs = start();
                let mut prows = rows.into_iter();
                let points: Vec<Vec<_>> =
                    (0..2).map(|_| (0..key_bits + 1).map(|_| fs.fp3()).collect()).collect();
                let mut values: [Fp3; 2] = std::array::from_fn(|plane| {
                    let (wk, wc) = (
                        crate::c71_matrix::eq(&points[plane][..key_bits]),
                        crate::c71_matrix::eq(&points[plane][key_bits..]),
                    );
                    (0..total).fold(Fp3::ZERO, |v, t| {
                        v + (0..2).fold(Fp3::ZERO, |v, c| {
                            v + wk[t] * wc[c] * signed(value(t / 3, first + plane, t % 3, c))
                        })
                    })
                });
                if fault == 1 && step == 2 {
                    values[0] += Fp3::ONE;
                }
                // Stand in for the already authenticated QK/PV originals.
                let (wire, originals) = range::authenticate(values, &mut prows);
                record_values(&mut fs, 0xfe, &wire);
                let requests: Vec<_> = (0..2)
                    .map(|i| Request {
                        source: first + i,
                        point: points[i].clone(),
                        original: originals[i],
                    })
                    .collect();
                let (proof, openings) = prove(
                    &s,
                    &requests,
                    |i, j| {
                        let x = models[i].weights[j] as u8;
                        if fault == 2 && step == 2 && i == 0 && j == alter {
                            x.wrapping_add(1)
                        } else {
                            x
                        }
                    },
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                let (rp, ranged, targets) = range::prove(
                    &models[step],
                    attempt,
                    bytes.layout_digest,
                    bytes.live,
                    range::Alphabet::Byte,
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                let mut ranged = Some((Vec::from(ranged), Vec::from(targets)));
                let mut proofs = Vec::new();
                for (i, o) in openings.into_iter().enumerate() {
                    let (mut forms, mut targets) =
                        if i == step { ranged.take().unwrap() } else { (Vec::new(), Vec::new()) };
                    forms.push(o.form);
                    targets.push(o.original);
                    proofs.push(
                        linear::prove(
                            &models[i],
                            attempt,
                            bytes.layout_digest,
                            &forms,
                            &targets,
                            &mut fs,
                            &mut prows,
                        )
                        .unwrap()
                        .0,
                    );
                }
                assert!(prows.next().is_none());
                let digest = fs.digest();
                let mut fs = start();
                let mut vrows = keys.into_iter();
                let points: Vec<Vec<_>> =
                    (0..2).map(|_| (0..key_bits + 1).map(|_| fs.fp3()).collect()).collect();
                let originals = range::correct(wire, delta, &mut vrows);
                record_values(&mut fs, 0xfe, &wire);
                let requests: Vec<_> = (0..2)
                    .map(|i| Request {
                        source: first + i,
                        point: points[i].clone(),
                        original: originals[i],
                    })
                    .collect();
                let openings = verify(&s, &requests, &proof, delta, &mut fs, &mut vrows).unwrap();
                let (ranged, targets) = range::verify(
                    32,
                    &models[step].root,
                    attempt,
                    bytes.layout_digest,
                    bytes.live,
                    range::Alphabet::Byte,
                    &rp,
                    delta,
                    &mut fs,
                    &mut vrows,
                )
                .unwrap();
                let mut ranged = Some((Vec::from(ranged), Vec::from(targets)));
                for (i, o) in openings.into_iter().enumerate() {
                    let (mut forms, mut targets) =
                        if i == step { ranged.take().unwrap() } else { (Vec::new(), Vec::new()) };
                    forms.push(o.form);
                    targets.push(o.original);
                    let result = linear::verify(
                        32,
                        &models[i].root,
                        attempt,
                        bytes.layout_digest,
                        &forms,
                        &targets,
                        &proofs[i],
                        delta,
                        &mut fs,
                        &mut vrows,
                    );
                    if result.is_err() {
                        assert!(step == 2 && fault != 0, "honest KV split rejected");
                        assert_eq!(i, if fault == 1 { 2 } else { 0 });
                        rejected = true;
                        break;
                    }
                }
                if rejected {
                    break;
                }
                assert_eq!(fs.digest(), digest);
                assert!(vrows.next().is_none());
                // Promote only after every relevant source opening accepted.
                receipts.push(*digest.as_bytes());
                let invalid =
                    Statement { attempt: AttemptContext { predecessor: [99; 32], ..attempt }, ..s };
                assert!(invalid.shape(&requests).is_err());
                assert!(Statement { model: [9; 32], ..s }.shape(&requests).is_err());
                if step > 0 {
                    let mut empty = Vec::<Auth>::new().into_iter();
                    let prequests: Vec<_> = requests
                        .iter()
                        .map(|r| Request {
                            source: r.source,
                            point: r.point.clone(),
                            original: Auth::ZERO,
                        })
                        .collect();
                    assert!(prove(
                        &s,
                        &prequests,
                        |_, _| panic!("KV read on exhaustion"),
                        &mut start(),
                        &mut empty
                    )
                    .is_err());
                }
            }
            assert_eq!(rejected, fault != 0);
            assert_eq!(receipts.len(), if fault == 0 { 3 } else { 2 });
        }
        // Metadata-only full tail forms: the same unaligned projection,
        // without allocating any canonical A or executing its PCS.
        let canonical = crate::c71_matrix::gemma::compile().unwrap().residual_sources().unwrap();
        let source = canonical.attention.layers[0].k;
        let bytes = &canonical.attention.rope.gate_up.gelu.rms.bytes;
        let row: Vec<_> = (0..9).map(|i| signed(i + 3)).collect();
        let column: Vec<_> = (0..12).map(|i| signed(i + 7)).collect();
        for (offset, count) in [(0, 4), (150, 75), (300, 38)] {
            let (form, _) =
                bytes.kv_segment_form(source, offset, 450, &row, &column, Fp3::ONE).unwrap();
            assert_eq!(form.len(), count);
        }
        assert!(bytes.kv_segment_form(source, 301, 450, &row, &column, Fp3::ONE).is_err());
    }
}

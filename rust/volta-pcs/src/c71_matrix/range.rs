//! Same-W range caller: private histogram, fraction-tree GKR, original MAC
//! endpoint. Reuses the LogUp tree relation, with native Fp3 and cubic rounds.
//! The caller closes the returned forms/targets in ONE linear PCS batch.

use super::*;
use linear::Cube;

pub(super) struct Layer {
    rounds: Vec<[Fp3; 5]>,
    split: [Fp3; 8], // four children, three products, one zero-MAC tag
}

pub(super) struct Proof {
    histogram: Vec<Fp3>,
    roots: [Fp3; 3], // numerator, denominator, denominator inverse
    layers: Vec<Layer>,
    leaf_tag: Fp3,
    products: [Fp3; 2],
}

pub(super) fn required(bits: usize, limit: i16) -> usize {
    2 * limit as usize + 1 + 2 * bits * bits + 5 * bits + 4
}

#[allow(clippy::too_many_arguments)]
fn bind(
    n: usize,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: i16,
    fs: &mut Fs,
) -> Result<usize, String> {
    let config = matrix_config(n)?;
    if limit < 1
        || live == 0
        || live > 1usize << config.num_variables
        || root.num_roots() != 1
        || !attempt.valid()
        || layout == [0; 32]
    {
        return Err("B12 range statement mismatch".into());
    }
    let mut bytes = b"C71-range-B12-v1;MSB-first;symmetric;zero-suffix;original-MAC".to_vec();
    bytes.extend(gamma(&config));
    bytes.extend((n as u32).to_le_bytes());
    bytes.extend(root.roots()[0]);
    bytes.extend(attempt.encode());
    bytes.extend(layout);
    bytes.extend((live as u64).to_le_bytes());
    bytes.extend(limit.to_le_bytes());
    fs.set_phase(0x400);
    fs.record(0x40, &bytes);
    Ok(config.num_variables)
}

// A public forbidden alpha is rejected independently of the private histogram.
fn challenges(bits: usize, limit: i16, fs: &mut Fs) -> Result<(Fp3, Vec<Fp3>, Vec<Fp3>), String> {
    let alpha = fs.fp3();
    let mut denominators = Vec::with_capacity(2 * limit as usize + 1);
    for t in -i64::from(limit)..=i64::from(limit) {
        let d = alpha - signed(t);
        if d == Fp3::ZERO {
            return Err("B12 range public pole".into());
        }
        denominators.push(d.inv());
    }
    let point: Vec<_> = (0..bits).map(|_| fs.fp3()).collect();
    Ok((alpha, denominators, point))
}

fn suffix(live: usize, point: &[Fp3]) -> Vec<Cube> {
    let mut offset = live;
    let mut result = Vec::new();
    while offset < 1usize << point.len() {
        let bits = offset.trailing_zeros() as usize;
        let prefix = point.len() - bits;
        let coefficient = point[..prefix].iter().enumerate().fold(Fp3::ONE, |s, (i, &r)| {
            s * if offset >> (point.len() - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        result.push(Cube { offset, point: point[prefix..].to_vec(), coefficient });
        offset += 1usize << bits;
    }
    result
}

pub(super) fn authenticate<const N: usize>(
    values: [Fp3; N],
    rows: &mut std::vec::IntoIter<Auth>,
) -> ([Fp3; N], [Auth; N]) {
    let mut wire = [Fp3::ZERO; N];
    let auth = std::array::from_fn(|i| {
        let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), values[i]);
        wire[i] = c.value();
        a
    });
    (wire, auth)
}

pub(super) fn correct<const N: usize>(
    wire: [Fp3; N],
    delta: Fp3,
    rows: &mut std::vec::IntoIter<Key>,
) -> [Key; N] {
    std::array::from_fn(|i| {
        c7_fp3_transfer_verifier(rows.next().unwrap(), delta, C7Fp3TransferCorrection::new(wire[i]))
    })
}

// One fresh mask for the ENTIRE ordered product batch, after every triple is
// fixed in the transcript. k=m+Delta*x. No division by lambda or Delta.
pub(super) fn prove_products(triples: &[[Auth; 3]], mask: Auth, fs: &mut Fs) -> [Fp3; 2] {
    fs.set_phase(0x600);
    let lambda = fs.fp3();
    let (mut a, mut b, mut power) = (mask.x, mask.m, Fp3::ONE);
    for &[x, y, z] in triples {
        a += power * (x.x * y.m + y.x * x.m - z.m);
        b += power * x.m * y.m;
        power = power * lambda;
    }
    record_values(fs, 0x45, &[a, b]);
    [a, b]
}

pub(super) fn verify_products(
    triples: &[[Key; 3]],
    mask: Key,
    wire: [Fp3; 2],
    delta: Fp3,
    fs: &mut Fs,
) -> Result<(), String> {
    fs.set_phase(0x600);
    let lambda = fs.fp3();
    let (mut expected, mut power) = (mask.k, Fp3::ONE);
    for &[x, y, z] in triples {
        expected += power * (x.k * y.k - delta * z.k);
        power = power * lambda;
    }
    if wire[1] + delta * wire[0] != expected {
        return Err("B12 range product MAC rejected".into());
    }
    record_values(fs, 0x45, &wire);
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn prove(
    model: &Model,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: i16,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, [Vec<Cube>; 2], [Auth; 2]), String> {
    let bits = bind(model.n, &model.root, attempt, layout, live, limit, fs)?;
    let count = required(bits, limit);
    if correlations.len() < count {
        return Err("B12 range prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let weights: Vec<_> = model
        .polynomial()
        .as_slice()
        .iter()
        .map(|x| Fp3::from_base(Fp::new(x.as_canonical_u64())))
        .collect();
    let mut histogram = vec![Fp3::ZERO; 2 * limit as usize + 1];
    for &w in &weights {
        let index = (w + signed(i64::from(limit))).c0.value();
        // A candidate with an out-of-range private witness is still provable
        // syntactically; the verifier's rational/product check must reject it.
        if index < histogram.len() as u64 {
            histogram[index as usize] += Fp3::ONE;
        }
    }
    let (histogram, authed): (Vec<_>, Vec<_>) = histogram
        .into_iter()
        .map(|h| {
            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), h);
            (c.value(), a)
        })
        .unzip();
    record_values(fs, 0x41, &histogram);
    let (alpha, inverse, rho) = challenges(bits, limit, fs)?;
    let h = authed.iter().zip(&inverse).fold(Auth::ZERO, |s, (&a, &d)| s.add(a.scale(d)));
    // ponytail: dense D<=14 component; full-size fraction-tree storage and
    // source reads need a separate schedule, never a D35 allocation here.
    let mut tree = vec![weights.iter().map(|&w| [Fp3::ONE, alpha - w]).collect::<Vec<_>>()];
    while tree.last().unwrap().len() > 1 {
        tree.push(
            tree.last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let ([p, q], [r, s]) = (pair[0], pair[1]);
                    [p * s + r * q, q * s]
                })
                .collect(),
        );
    }
    let [p, q] = tree.last().unwrap()[0];
    if q == Fp3::ZERO {
        return Err("B12 range witness pole".into());
    }
    let (roots, root) = authenticate([p, q, q.inv()], &mut rows);
    fs.set_phase(0x401);
    record_values(fs, 0x42, &roots);
    let mut triples =
        vec![[h, root[1], root[0]], [root[1], root[2], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let (mut claims, mut point, mut layers) = ([root[0], root[1]], Vec::new(), Vec::new());
    for l in 0..bits {
        let lambda = fs.fp3();
        let mut target = claims[0].scale(lambda).add(claims[1]);
        let level = &tree[bits - 1 - l];
        let mut children: [Vec<Fp3>; 4] =
            std::array::from_fn(|j| level.chunks_exact(2).map(|pair| pair[j / 2][j % 2]).collect());
        let mut equality = eq(&point);
        let (mut next_point, mut rounds) = (Vec::new(), Vec::new());
        for round in 0..l {
            fs.set_phase(0x500 + (32 * l + round) as u16);
            let half = equality.len() / 2;
            let mut c = [Fp3::ZERO; 4];
            for i in 0..half {
                let a: [Fp3; 4] = std::array::from_fn(|j| children[j][i]);
                let d: [Fp3; 4] = std::array::from_fn(|j| children[j][i + half] - a[j]);
                let mut v = [Fp3::ZERO; 3];
                for (x, y, coefficient) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
                    v[0] += coefficient * a[x] * a[y];
                    v[1] += coefficient * (d[x] * a[y] + a[x] * d[y]);
                    v[2] += coefficient * d[x] * d[y];
                }
                let de = equality[i + half] - equality[i];
                for j in 0..3 {
                    c[j] += equality[i] * v[j];
                    c[j + 1] += de * v[j];
                }
            }
            let (corrections, a) = authenticate(c, &mut rows);
            let tag = a[0].m + a[0].m + a[1].m + a[2].m + a[3].m - target.m;
            let wire = [corrections[0], corrections[1], corrections[2], corrections[3], tag];
            record_values(fs, 0x43, &wire);
            let r = fs.fp3();
            target = a.iter().rev().fold(Auth::ZERO, |s, &x| s.scale(r).add(x));
            for child in &mut children {
                fold(child, r);
            }
            fold(&mut equality, r);
            next_point.push(r);
            rounds.push(wire);
        }
        let [p, q, r, s] = std::array::from_fn(|i| children[i][0]);
        let (wire, a) = authenticate([p, q, r, s, p * s, r * q, q * s], &mut rows);
        triples.extend([[a[0], a[3], a[4]], [a[2], a[1], a[5]], [a[1], a[3], a[6]]]);
        let residual = a[4].add(a[5]).scale(lambda).add(a[6]).scale(equality[0]);
        let split =
            [wire[0], wire[1], wire[2], wire[3], wire[4], wire[5], wire[6], residual.m - target.m];
        fs.set_phase(0x410 + l as u16);
        record_values(fs, 0x44, &split);
        let t = fs.fp3();
        claims = [
            a[0].scale(Fp3::ONE - t).add(a[2].scale(t)),
            a[1].scale(Fp3::ONE - t).add(a[3].scale(t)),
        ];
        next_point.push(t);
        point = next_point;
        layers.push(Layer { rounds, split });
    }
    let leaf_tag = claims[0].m; // numerator is the constant one at every leaf
    record_values(fs, 0x46, &[leaf_tag]);
    let products = prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    let target = Auth::new(alpha - claims[1].x, -claims[1].m);
    let forms = [vec![Cube { offset: 0, point, coefficient: Fp3::ONE }], suffix(live, &rho)];
    Ok((Proof { histogram, roots, layers, leaf_tag, products }, forms, [target, Auth::ZERO]))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn verify(
    n: usize,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: i16,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<([Vec<Cube>; 2], [Key; 2]), String> {
    let bits = bind(n, root, attempt, layout, live, limit, fs)?;
    let count = required(bits, limit);
    if proof.histogram.len() != 2 * limit as usize + 1
        || proof.layers.len() != bits
        || proof.layers.iter().enumerate().any(|(i, layer)| layer.rounds.len() != i)
        || correlations.len() < count
    {
        return Err("B12 range proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let histogram: Vec<_> =
        proof.histogram.iter().map(|&c| correct([c], delta, &mut rows)[0]).collect();
    record_values(fs, 0x41, &proof.histogram);
    let (alpha, inverse, rho) = challenges(bits, limit, fs)?;
    let h = histogram.iter().zip(&inverse).fold(Key::ZERO, |s, (&a, &d)| s.add(a.scale(d)));
    let root = correct(proof.roots, delta, &mut rows);
    fs.set_phase(0x401);
    record_values(fs, 0x42, &proof.roots);
    let mut triples = vec![[h, root[1], root[0]], [root[1], root[2], Key::new(delta)]];
    let (mut claims, mut point) = ([root[0], root[1]], Vec::<Fp3>::new());
    for (l, layer) in proof.layers.iter().enumerate() {
        let lambda = fs.fp3();
        let mut target = claims[0].scale(lambda).add(claims[1]);
        let (mut equality, mut next_point) = (Fp3::ONE, Vec::new());
        for (round, wire) in layer.rounds.iter().enumerate() {
            fs.set_phase(0x500 + (32 * l + round) as u16);
            let a = correct([wire[0], wire[1], wire[2], wire[3]], delta, &mut rows);
            if a[0].k + a[0].k + a[1].k + a[2].k + a[3].k - target.k != wire[4] {
                return Err("B12 range cubic MAC rejected".into());
            }
            record_values(fs, 0x43, wire);
            let r = fs.fp3();
            target = a.iter().rev().fold(Key::ZERO, |s, &x| s.scale(r).add(x));
            equality = equality * ((Fp3::ONE - point[round]) * (Fp3::ONE - r) + point[round] * r);
            next_point.push(r);
        }
        let a = correct(std::array::from_fn::<_, 7, _>(|i| layer.split[i]), delta, &mut rows);
        triples.extend([[a[0], a[3], a[4]], [a[2], a[1], a[5]], [a[1], a[3], a[6]]]);
        let residual = a[4].add(a[5]).scale(lambda).add(a[6]).scale(equality);
        if residual.k - target.k != layer.split[7] {
            return Err("B12 range split MAC rejected".into());
        }
        fs.set_phase(0x410 + l as u16);
        record_values(fs, 0x44, &layer.split);
        let t = fs.fp3();
        claims = [
            a[0].scale(Fp3::ONE - t).add(a[2].scale(t)),
            a[1].scale(Fp3::ONE - t).add(a[3].scale(t)),
        ];
        next_point.push(t);
        point = next_point;
    }
    if claims[0].k - delta != proof.leaf_tag {
        return Err("B12 range leaf MAC rejected".into());
    }
    record_values(fs, 0x46, &[proof.leaf_tag]);
    verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    debug_assert!(rows.next().is_none());
    let target = Key::new(delta * alpha - claims[1].k);
    let forms = [vec![Cube { offset: 0, point, coefficient: Fp3::ONE }], suffix(live, &rho)];
    Ok((forms, [target, Key::ZERO]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> AttemptContext {
        AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        }
    }

    fn transcript(n: usize) -> Fs {
        Fs::new(b"B12 same-root range component", request_limit(&matrix_config(n).unwrap()) + 256)
    }

    #[test]
    fn c71_b12_range_i16_and_padding_close_the_original_leaf_mac() {
        use rand_010::RngExt;
        let n = 32;
        let bits = 10;
        let layout = [4; 32];
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        let mut rng = MatrixRng::from_seed([101; 32]);
        for (first, padding, range_ok) in
            [(-32767, 0, true), (32767, 0, true), (-32768, 0, false), (7, 1, true)]
        {
            let mut weights = vec![0; n * n];
            weights[..7].copy_from_slice(&[first, -2, 3, 0, 17, -31, 1]);
            weights[23] = padding;
            let model = Model::new(n, weights).unwrap();
            let required = required(bits, 32767) + 3 * bits + 2;
            assert_eq!(required, 65821);
            let rows: Vec<_> = (0..required)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let mut rows = rows.into_iter();
            let mut fs = transcript(n);
            let (mut range, forms, targets) =
                prove(&model, context(), layout, 7, 32767, &mut fs, &mut rows).unwrap();
            assert_eq!(fs.requests(), 77);
            let (pcs, digest) =
                linear::prove(&model, context(), layout, &forms, &targets, &mut fs, &mut rows)
                    .unwrap();
            assert!(rows.next().is_none());
            let check = |proof: &Proof, detach: bool| {
                let mut rows = keys.clone().into_iter();
                let mut fs = transcript(n);
                let (forms, mut targets) = verify(
                    n,
                    &model.root,
                    context(),
                    layout,
                    7,
                    32767,
                    proof,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                if detach {
                    targets[0].k += Fp3::ONE;
                }
                let checked = linear::verify(
                    n,
                    &model.root,
                    context(),
                    layout,
                    &forms,
                    &targets,
                    &pcs,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                assert!(rows.next().is_none());
                Ok::<_, String>(checked)
            };
            if !range_ok {
                assert_eq!(check(&range, false).unwrap_err(), "B12 range product MAC rejected");
            } else if padding != 0 {
                assert_eq!(check(&range, false).unwrap_err(), "C71 matrix sumcheck MAC rejected");
            } else {
                assert_eq!(check(&range, false).unwrap(), digest);
                assert!(check(&range, true).is_err());
                range.histogram[0] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.histogram[0] += -Fp3::ONE;
                range.roots[2] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.roots[2] += -Fp3::ONE;
                range.layers[3].rounds[1][2] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.layers[3].rounds[1][2] += -Fp3::ONE;
                range.products[0] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.products[0] += -Fp3::ONE;
                range.leaf_tag += Fp3::ONE;
                assert!(check(&range, false).is_err());
            }
        }
        let root = C61Commitment::new(vec![[9; 32]]);
        for (live, limit) in [(0, 3), (1025, 3), (7, 0), (7, -1)] {
            assert!(bind(n, &root, context(), layout, live, limit, &mut transcript(n)).is_err());
        }
    }

    #[test]
    fn c71_b12_product_batch_uses_one_fresh_mask_and_the_native_sign() {
        let x = Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5));
        let y = Fp3::new(Fp::new(7), Fp::new(11), Fp::new(13));
        for delta in [Fp3::ZERO, Fp3::ONE, x] {
            let a = Auth::new(x, y);
            let b = Auth::new(y, x);
            let c = Auth::new(x * y, x + y);
            let mask = Auth::new(y * y, x * x);
            let triples = [[a, b, c], [b, a, c]];
            let key = |a: Auth| Key::new(a.m + delta * a.x);
            let keys = triples.map(|t| t.map(key));
            let mut fs = Fs::new(b"product algebra", 1);
            let wire = prove_products(&triples, mask, &mut fs);
            verify_products(&keys, key(mask), wire, delta, &mut Fs::new(b"product algebra", 1))
                .unwrap();
            assert!(verify_products(
                &keys,
                key(mask),
                [wire[0], wire[1] + Fp3::ONE],
                delta,
                &mut Fs::new(b"product algebra", 1)
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_range_real_fixed_pool_accepts_then_ends_on_a_false_range() {
        use std::{io, sync::mpsc, time::Duration};
        use volta_pcg::c71_lifetime::{Attempt, Lifetime, ModelBinding};
        let n = 32;
        let mut weights = vec![0; n * n];
        weights[..7].copy_from_slice(&[2, -3, 1, 0, -2, 3, -1]);
        let model = Model::new(n, weights).unwrap();
        let root = model.root.clone();
        let layout = [4; 32];
        let binding =
            ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: layout };
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-b12-range-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ppath = directory.join("prover");
        let vpath = directory.join("verifier");
        let prover_path = ppath.clone();
        let count = |limit| required(10, limit) + 32;
        let capacity = 3 * (count(3) + count(1));
        assert_eq!(capacity, 1746);
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let context = |a: &Attempt| AttemptContext {
            session: [1; 32],
            capacity: a.capacity,
            slot: (a.ordinal - 1) as u8,
            predecessor: a.predecessor,
            nonce: [3; 32],
        };
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for channel in [&pc, &vc] {
            channel.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            channel.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let (send, receive) = mpsc::sync_channel(1);
        let (ack, wait_ack) = mpsc::sync_channel(1);
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let mut pool = store.prover_fixed_run(&mut pc, [1; 32], [2; 32], capacity).unwrap();
            for limit in [3, 1] {
                pool.attempt(count(limit), |attempt, rows, _| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| {
                            let tag = |a: [u64; 4]| field([a[1], a[2], a[3]]);
                            Auth::new(
                                field([r[0][0], r[1][0], r[2][0]]),
                                tag(r[0]) + u * tag(r[1]) + u * u * tag(r[2]),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_iter();
                    let attempt = context(&attempt);
                    let mut fs = transcript(n);
                    let (range, forms, targets) =
                        prove(&model, attempt, layout, 7, limit, &mut fs, &mut rows)
                            .map_err(io::Error::other)?;
                    let (pcs, digest) = linear::prove(
                        &model, attempt, layout, &forms, &targets, &mut fs, &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert!(rows.next().is_none());
                    send.send((range, pcs, digest)).unwrap();
                    let head = wait_ack.recv_timeout(Duration::from_secs(45)).unwrap();
                    assert_eq!(head, if limit == 3 { Some(*digest.as_bytes()) } else { None });
                    Ok(((), head))
                })
                .unwrap();
            }
            assert!(pool.attempt::<()>(1, |_, _, _| panic!("failed range continued")).is_err());
        });
        let mut store = Lifetime::install(&vpath, binding).unwrap();
        let mut pool = store.verifier_fixed_run(&mut vc, [1; 32], [2; 32], capacity).unwrap();
        for limit in [3, 1] {
            let head = pool
                .attempt(count(limit), |attempt, rows, delta| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| Key::new(field(r[0]) + u * field(r[1]) + u * u * field(r[2])))
                        .collect::<Vec<_>>()
                        .into_iter();
                    let delta = -field(*delta.unwrap());
                    let attempt = context(&attempt);
                    let (range, pcs, digest) =
                        receive.recv_timeout(Duration::from_secs(45)).unwrap();
                    let mut fs = transcript(n);
                    let checked = verify(
                        n, &root, attempt, layout, 7, limit, &range, delta, &mut fs, &mut rows,
                    );
                    if limit == 1 {
                        assert_eq!(checked.err().unwrap(), "B12 range product MAC rejected");
                        return Ok((None, None));
                    }
                    let (forms, targets) = checked.map_err(io::Error::other)?;
                    let checked = linear::verify(
                        n, &root, attempt, layout, &forms, &targets, &pcs, delta, &mut fs,
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert_eq!(checked, digest);
                    assert!(rows.next().is_none());
                    Ok((Some(*checked.as_bytes()), Some(*checked.as_bytes())))
                })
                .unwrap();
            ack.send(head).unwrap();
        }
        assert!(pool.attempt::<()>(1, |_, _, _| panic!("rejected range continued")).is_err());
        prover.join().unwrap();
        drop(pool);
        drop(store);
        for path in [ppath, vpath] {
            assert!(Lifetime::open(&path, binding).is_err());
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}

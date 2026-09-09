//! B12 component: open an ordered batch of public linear forms against one
//! installed root, starting from the caller's ORIGINAL authenticated targets.
//! The Gemma compiler, i16 range proof and full-size prover remain separate.

use super::*;

/// EQ-supported aligned cube in the root's Boolean table. Both this point
/// and the PCS use most-significant-variable first (Python W-cut uses LSB).
#[derive(Clone)]
pub(super) struct Cube {
    pub offset: usize,
    pub point: Vec<Fp3>,
    pub coefficient: Fp3,
}

impl Cube {
    fn at(&self, point: &[Fp3]) -> Fp3 {
        let prefix = point.len() - self.point.len();
        let index = self.offset >> self.point.len();
        let high = point[..prefix].iter().enumerate().fold(Fp3::ONE, |s, (i, &r)| {
            s * if index >> (prefix - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        self.coefficient
            * high
            * self
                .point
                .iter()
                .zip(&point[prefix..])
                .fold(Fp3::ONE, |s, (&r, &t)| s * ((Fp3::ONE - r) * (Fp3::ONE - t) + r * t))
    }
}

/// Bind the public forms after the caller's target-correction messages and
/// before lambda. No value/tag/key is serialized here, and no new MAC for
/// the aggregate is requested. One root, one batch, one PCS chain.
fn bind(
    n: usize,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    count: usize,
    fs: &mut Fs,
) -> Result<(ZkWhirConfig<E, Goldilocks, Fs>, Vec<Fp3>), String> {
    let config = matrix_config(n)?;
    let bits = config.num_variables;
    if root.num_roots() != 1
        || !attempt.valid()
        || layout == [0; 32]
        || forms.is_empty()
        || forms.len() > 4096
        || count != forms.len()
        || forms.iter().map(Vec::len).sum::<usize>() > 16384
    {
        return Err("B12 linear batch shape, layout or attempt mismatch".into());
    }
    let mut bytes = b"C71-linear-B12-v1;MSB-first;original-target-MACs;one-PCS".to_vec();
    bytes.extend(gamma(&config));
    bytes.extend((n as u32).to_le_bytes());
    bytes.extend(root.roots()[0]);
    bytes.extend(attempt.encode());
    bytes.extend(layout);
    bytes.extend((forms.len() as u32).to_le_bytes());
    for form in forms {
        bytes.extend((form.len() as u32).to_le_bytes());
        for cube in form {
            if cube.point.len() > bits {
                return Err("B12 linear cube arity exceeds root domain".into());
            }
            let size = 1usize << cube.point.len();
            if cube.offset % size != 0
                || cube.offset.checked_add(size).is_none_or(|end| end > 1usize << bits)
            {
                return Err("B12 linear cube is unaligned or outside root domain".into());
            }
            bytes.extend((cube.offset as u64).to_le_bytes());
            bytes.extend((cube.point.len() as u32).to_le_bytes());
            bytes.extend(cube.coefficient.to_bytes());
            for x in &cube.point {
                bytes.extend(x.to_bytes());
            }
        }
    }
    fs.set_phase(0x300);
    fs.record(0x30, &bytes);
    let lambda = fs.fp3();
    let mut power = Fp3::ONE;
    let coefficients = forms
        .iter()
        .map(|_| {
            let next = power;
            power = power * lambda;
            next
        })
        .collect();
    Ok((config, coefficients))
}

// The caller reserves/burns 3*D+2 fresh correlations and its target transfers
// before entering. fs already contains the original target-correction wire.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove(
    model: &Model,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Auth],
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    let required = 3 * matrix_config(model.n)?.num_variables + 2;
    if correlations.len() < required {
        return Err("B12 linear prover correlations exhausted".into());
    }
    let mut reserved = correlations.by_ref().take(required).collect::<Vec<_>>().into_iter();
    let (config, coefficients) =
        bind(model.n, &model.root, attempt, layout, forms, targets.len(), fs)?;
    let target =
        targets.iter().zip(&coefficients).fold(Auth::ZERO, |s, (&x, &c)| s.add(x.scale(c)));
    let mut form = vec![Fp3::ZERO; 1usize << config.num_variables];
    for (cubes, &coefficient) in forms.iter().zip(&coefficients) {
        for cube in cubes {
            for (i, weight) in eq(&cube.point).into_iter().enumerate() {
                form[cube.offset + i] += coefficient * cube.coefficient * weight;
            }
        }
    }
    // ponytail: dense D<=14 component only; a full Gemma caller needs the
    // existing streaming/tiled source plan, never a D35 dense allocation.
    let weights = model
        .polynomial()
        .as_slice()
        .iter()
        .map(|x| Fp3::from_base(Fp::new(x.as_canonical_u64())))
        .collect();
    let (rounds, point, target, value, public_endpoint) =
        prove_product(weights, form, target, fs, &mut reserved);
    fs.set_phase(0x100);
    let (correction, terminal) = c7_fp3_transfer_prover(reserved.next().unwrap(), value);
    let terminal_wire = [correction.value(), target.m - public_endpoint * terminal.m];
    record_values(fs, 0x11, &terminal_wire);
    let mask = reserved.next().unwrap();
    let point = Point::new(point.into_iter().map(to_p3).collect());
    let (pcs, close_tag) = prove_pcs(model, &config, point, terminal, mask, fs)?;
    Ok((MatrixProof { rounds, terminal: terminal_wire, pcs, close_tag }, fs.digest()))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    n: usize,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Key],
    proof: &MatrixProof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<blake3::Hash, String> {
    let bits = matrix_config(n)?.num_variables;
    let required = 3 * bits + 2;
    if correlations.len() < required || proof.rounds.len() != bits {
        return Err("B12 linear verifier correlations or round count mismatch".into());
    }
    let mut reserved = correlations.by_ref().take(required).collect::<Vec<_>>().into_iter();
    let (config, coefficients) = bind(n, root, attempt, layout, forms, targets.len(), fs)?;
    let target = targets.iter().zip(&coefficients).fold(Key::ZERO, |s, (&x, &c)| s.add(x.scale(c)));
    let (target, point) = verify_product(&proof.rounds, target, delta, fs, &mut reserved)?;
    // O(D * cube count) verifier work: no N-cell public form or W.
    let public_endpoint = forms.iter().zip(&coefficients).fold(Fp3::ZERO, |s, (cubes, &c)| {
        s + c * cubes.iter().fold(Fp3::ZERO, |v, cube| v + cube.at(&point))
    });
    fs.set_phase(0x100);
    let terminal = c7_fp3_transfer_verifier(
        reserved.next().unwrap(),
        delta,
        C7Fp3TransferCorrection::new(proof.terminal[0]),
    );
    if target.k - public_endpoint * terminal.k != proof.terminal[1] {
        return Err("B12 linear terminal MAC rejected".into());
    }
    record_values(fs, 0x11, &proof.terminal);
    let mask = reserved.next().unwrap();
    let point = Point::new(point.into_iter().map(to_p3).collect());
    verify_pcs(&config, root, point, &proof.pcs, proof.close_tag, terminal, mask, delta, fs)?;
    Ok(fs.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_cube_evaluator_matches_dense_forms_and_rejects_bad_layout() {
        let point: Vec<_> = (0..10).map(|i| Fp3::new(Fp::new(i + 2), Fp::ONE, Fp::ONE)).collect();
        let rho = eq(&point);
        for bits in 0..=10 {
            for offset in (0..1024).step_by(1 << bits) {
                let cube = Cube { offset, point: point[..bits].to_vec(), coefficient: signed(-7) };
                let expected = eq(&cube.point)
                    .iter()
                    .enumerate()
                    .fold(Fp3::ZERO, |s, (i, &r)| s + cube.coefficient * r * rho[offset + i]);
                assert_eq!(cube.at(&point), expected);
            }
        }
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let root = C61Commitment::new(vec![[4; 32]]);
        for cube in [
            Cube { offset: 1, point: vec![Fp3::ONE], coefficient: Fp3::ONE },
            Cube { offset: 1024, point: vec![], coefficient: Fp3::ONE },
            Cube { offset: 0, point: vec![Fp3::ONE; 11], coefficient: Fp3::ONE },
            Cube { offset: usize::MAX, point: vec![], coefficient: Fp3::ONE },
        ] {
            assert!(bind(
                32,
                &root,
                attempt,
                [5; 32],
                &[vec![cube]],
                1,
                &mut Fs::new(b"bad cube", 0)
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_real_pool_linear_batch_keeps_matrix_norm_and_tied_embedding_macs() {
        check_real_pool_linear_batch(false);
    }

    #[test]
    fn c71_b12_fixed_run_linear_batch_accepts_then_stops_on_false_target() {
        check_real_pool_linear_batch(true);
    }

    fn check_real_pool_linear_batch(fixed_run: bool) {
        use std::io;
        use std::sync::mpsc;
        use volta_pcg::c71_lifetime::{Attempt, Lifetime, ModelBinding};

        let n = 32;
        let mut weights = vec![0i16; n * n];
        weights[..11].copy_from_slice(&[2, -3, 5, 7, -11, 13, 17, -19, 23, -29, 31]);
        weights[16..24].copy_from_slice(&[37, -41, 43, 47, -53, 59, 61, -67]);
        let cube = |offset, point: &[i64], coefficient| Cube {
            offset,
            point: point.iter().map(|&x| signed(x)).collect(),
            coefficient: signed(coefficient),
        };
        let forms = vec![
            vec![cube(0, &[2, 5, 7], 1)],              // matrix 2 x 4
            vec![cube(8, &[3], 7), cube(10, &[], 11)], // ragged norm, width 3
            vec![cube(20, &[13], 1)],                  // embedding token 2
            vec![cube(16, &[2, 3, 17], 1)],            // logits: SAME embedding
        ];
        // Independent contractions of the tiny operator outputs, not reads
        // through Cube::at or the prover's dense-form construction.
        let matrix_input = [24, -28, -30, 35];
        let matrix_outputs: Vec<i64> = weights[..8]
            .chunks_exact(4)
            .map(|row| row.iter().zip(matrix_input).map(|(&w, x)| i64::from(w) * x).sum())
            .collect();
        let logits: Vec<i64> = weights[16..24]
            .chunks_exact(2)
            .map(|row| -16 * i64::from(row[0]) + 17 * i64::from(row[1]))
            .collect();
        let targets = [
            -matrix_outputs[0] + 2 * matrix_outputs[1],
            -14 * i64::from(weights[8]) + 21 * i64::from(weights[9]) + 11 * i64::from(weights[10]),
            -12 * i64::from(weights[20]) + 13 * i64::from(weights[21]),
            2 * logits[0] - 3 * logits[1] - 4 * logits[2] + 6 * logits[3],
        ]
        .map(signed);
        let model = Model::new(n, weights).unwrap();
        let root = model.root.clone();
        let layout = *blake3::hash(b"tiny matrix[0,8);norm[8,11);tied-embedding[16,24)").as_bytes();
        let binding =
            ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: layout };
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-b12-linear-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ppath = directory.join("prover");
        let vpath = directory.join("verifier");
        let prover_path = ppath.clone();
        let required = 4 + 3 * matrix_config(n).unwrap().num_variables + 2;
        assert_eq!(required * 3, 108);
        let bad_required = required - 3; // one falsely claimed norm target
        assert_eq!(3 * (required + bad_required), 207);
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let context = |a: &Attempt| AttemptContext {
            session: [4; 32],
            capacity: a.capacity,
            slot: (a.ordinal - 1) as u8,
            predecessor: a.predecessor,
            nonce: [6; 32],
        };
        let start = move |corrections: &[Fp3]| {
            let mut fs = Fs::new(
                b"B12 tiny operator caller; not a Gemma trace",
                request_limit(&matrix_config(n).unwrap()) + 1,
            );
            record_values(&mut fs, 0x31, corrections);
            fs
        };
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for channel in [&pc, &vc] {
            channel.set_read_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
            channel.set_write_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
        }
        // In-memory proof transport only; this test does not claim a wire
        // codec, a compiler-emitted GKR trace or a complete Gemma execution.
        let (send, receive) = mpsc::sync_channel(1);
        let (ack, wait_ack) = mpsc::sync_channel(1);
        let pforms = forms.clone();
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let capacity = 3 * (required + bad_required);
            let mut pool = if fixed_run {
                store.prover_fixed_run(&mut pc, [4; 32], [5; 32], capacity)
            } else {
                store.prover(&mut pc, [4; 32], [5; 32], capacity)
            }
            .unwrap();
            for (slot, count) in [required, bad_required].into_iter().enumerate() {
                pool.attempt(count, |attempt, rows, _| {
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
                    let values =
                        if slot == 0 { targets.to_vec() } else { vec![targets[1] + Fp3::ONE] };
                    let current_forms = if slot == 0 { &pforms[..] } else { &pforms[1..2] };
                    let (corrections, original): (Vec<_>, Vec<_>) = values
                        .into_iter()
                        .map(|x| {
                            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), x);
                            (c.value(), a)
                        })
                        .unzip();
                    let mut fs = start(&corrections);
                    let (proof, digest) = prove(
                        &model,
                        context(&attempt),
                        layout,
                        current_forms,
                        &original,
                        &mut fs,
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert!(rows.next().is_none());
                    send.send((proof, corrections, digest)).unwrap();
                    let accepted =
                        wait_ack.recv_timeout(std::time::Duration::from_secs(40)).unwrap();
                    assert_eq!(accepted, if slot == 0 { *digest.as_bytes() } else { [0; 32] });
                    Ok(((), (slot == 0).then_some(accepted)))
                })
                .unwrap();
            }
            assert!(pool.attempt::<()>(1, |_, _, _| panic!("exhausted capacity reused")).is_err());
        });
        let mut store = Lifetime::install(&vpath, binding).unwrap();
        let capacity = 3 * (required + bad_required);
        let mut pool = if fixed_run {
            store.verifier_fixed_run(&mut vc, [4; 32], [5; 32], capacity)
        } else {
            store.verifier(&mut vc, [4; 32], [5; 32], capacity)
        }
        .unwrap();
        for (slot, count) in [required, bad_required].into_iter().enumerate() {
            let head = pool
                .attempt(count, |attempt, rows, delta| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| Key::new(field(r[0]) + u * field(r[1]) + u * u * field(r[2])))
                        .collect::<Vec<_>>()
                        .into_iter();
                    let delta = Fp3::ZERO - field(*delta.unwrap());
                    let (proof, corrections, digest) =
                        receive.recv_timeout(std::time::Duration::from_secs(40)).unwrap();
                    let original: Vec<_> = corrections
                        .iter()
                        .map(|&c| {
                            c7_fp3_transfer_verifier(
                                rows.next().unwrap(),
                                delta,
                                C7Fp3TransferCorrection::new(c),
                            )
                        })
                        .collect();
                    let attempt = context(&attempt);
                    if slot == 1 {
                        // Fresh rows, fresh proof, same root: the prover has validly
                        // authenticated norm(W)+1. Correct MACs alone must not pass.
                        let rejected = verify(
                            n,
                            &root,
                            attempt,
                            layout,
                            &forms[1..2],
                            &original,
                            &proof,
                            delta,
                            &mut start(&corrections),
                            &mut rows,
                        );
                        assert_eq!(rejected.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                        assert!(rows.next().is_none()); // the whole attempt was reserved
                        return Ok((None, None));
                    }
                    // Counterfactual verifier replays of ONE proof: no new prover
                    // emission or correlation use; these are rejection diagnostics.
                    let check =
                        |root: &C61Commitment, layout, forms: &[Vec<Cube>], keys: &[Key]| {
                            verify(
                                n,
                                root,
                                attempt,
                                layout,
                                forms,
                                keys,
                                &proof,
                                delta,
                                &mut start(&corrections),
                                &mut rows.clone(),
                            )
                        };
                    for index in 0..original.len() {
                        let mut detached = original.clone();
                        detached[index].k += delta; // another valid MAC, plaintext shifted by one
                        assert!(check(&root, layout, &forms, &detached).is_err());
                    }
                    let mut other = forms.clone();
                    other[2][0].offset = 18; // lookup switched to another embedding row
                    assert!(check(&root, layout, &other, &original).is_err());
                    assert!(check(&root, [7; 32], &forms, &original).is_err());
                    assert!(check(&C61Commitment::new(vec![[8; 32]]), layout, &forms, &original)
                        .is_err());
                    let checked = verify(
                        n,
                        &root,
                        attempt,
                        layout,
                        &forms,
                        &original,
                        &proof,
                        delta,
                        &mut start(&corrections),
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert_eq!(checked, digest);
                    assert!(rows.next().is_none());
                    Ok((Some(*checked.as_bytes()), Some(*checked.as_bytes())))
                })
                .unwrap();
            ack.send(head.unwrap_or([0; 32])).unwrap(); // head synced before acknowledgement
        } // the failed second attempt terminates this uninterrupted run
        prover.join().unwrap();
        drop(pool);
        drop(store);
        for path in [ppath, vpath] {
            if fixed_run {
                assert!(Lifetime::open(&path, binding).is_err());
            }
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}

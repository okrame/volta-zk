use super::*;
use byte_function::batch;
use linear::Cube;
use rand_010::RngExt;
use wire::Wire;

fn bytes(value: i64) -> [u8; 6] {
    (value + (1 << 47)).to_le_bytes()[..6].try_into().unwrap()
}

#[test]
fn c71_rne_unpadded_groups_cover_without_extra_cells() {
    for point in [vec![], vec![signed(2)], vec![signed(3), signed(5), signed(7)]] {
        for scale in [Fp3::ZERO, Fp3::ONE, signed(11)] {
            assert_eq!(
                eq_scaled(&point, scale),
                eq(&point).into_iter().map(|v| v * scale).collect::<Vec<_>>()
            );
        }
    }
    assert!(batch::unpadded_groups(&[]).is_err());
    assert!(batch::unpadded_groups(&[35]).is_err());
    for n in 1..100 {
        let bits: Vec<_> = (0..n).map(|i| (i * 7 + n) % 12).collect();
        let groups = batch::unpadded_groups(&bits).unwrap();
        let mut seen = Vec::new();
        for group in groups {
            let local: Vec<_> = group.iter().map(|&i| bits[i]).collect();
            let (d, _) = batch::geometry(&local).unwrap();
            assert_eq!(1usize << d, local.iter().map(|&b| 1usize << b).sum::<usize>());
            seen.extend(group);
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..n).collect::<Vec<_>>());
    }
    assert_eq!(batch::unpadded_groups(&[34, 34]).unwrap(), vec![vec![0], vec![1]]);
}

#[test]
fn c71_b12_rne_joint_bytes_valid_proofs_and_original_pcs() {
    let n = 32;
    let profile = gamma(&matrix_config(n).unwrap());
    let attempt = AttemptContext {
        session: [1; 32],
        capacity: [2; 32],
        slot: 0,
        predecessor: [0; 32],
        nonce: [3; 32],
    };
    let points = [vec![signed(3), signed(11)], vec![signed(7)]];
    let shifts = [2, 1];
    let (d, offsets) = batch::geometry(&[5, 4]).unwrap();
    assert_eq!((d, offsets.clone()), (6, vec![0, 32]));
    assert_eq!(batch::geometry(&[4, 5]).unwrap(), (6, vec![32, 0]));
    assert!(batch::geometry(&[]).is_err());
    assert!(batch::geometry(&[34, 34]).is_err());
    assert_eq!(batch::groups(&[34, 34]).unwrap(), vec![vec![0], vec![1]]);
    let reduction_rows: usize = (0..2)
        .map(|i| {
            required(points[i].len(), shifts[i]) - byte_function::required(points[i].len() + 3)
        })
        .sum();
    let count =
        2 + reduction_rows + batch::required(d) + range::required(10, range::Alphabet::Byte) + 32;
    let delta = signed(19);
    let mut rng = MatrixRng::from_seed([193; 32]);
    let rows: Vec<_> = (0..count)
        .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
        .collect();
    let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
    for fault in 0..6 {
        let mut raw = [vec![-6, -10, 14], vec![-7, 11]];
        let mut outputs = [vec![-2i64, -2, 4], vec![-4, 6]];
        if fault == 1 {
            outputs[0][0] = -1;
        }
        let mut source = vec![0i16; n * n];
        for i in 0..2 {
            for (cell, &r) in raw[i].iter().enumerate() {
                for (lane, b) in bytes(r).into_iter().enumerate() {
                    source[128 * (i + 1) + 8 * cell + lane] = i16::from(b);
                }
            }
            for (cell, &y) in outputs[i].iter().enumerate() {
                for (lane, b) in (y + 32768).to_le_bytes()[..2].iter().enumerate() {
                    source[64 + 8 * i + 2 * cell + lane] = i16::from(*b);
                }
            }
        }
        let model = Model::new(n, source).unwrap();
        let statements: Vec<_> = (0..2)
            .map(|i| Statement {
                root: &model.root,
                profile: &profile,
                view: [30 + i as u8; 32],
                attempt,
                output_point: &points[i],
                shape: [raw[i].len(), 1],
                shift: shifts[i],
            })
            .collect();
        let values: [Fp3; 2] = std::array::from_fn(|i| {
            outputs[i].iter().zip(eq(&points[i])).fold(Fp3::ZERO, |v, (&y, r)| v + signed(y) * r)
        });
        let start =
            || Fs::new(b"C71 joint RNE experiment; two original outputs; one source", 100_000);
        let mut fs = start();
        let mut prows = rows.clone().into_iter();
        let (output_wire, original) = range::authenticate(values, &mut prows);
        record_values(&mut fs, 0x74, &output_wire);
        if fault == 2 {
            raw[0][0] = -7;
        } // Same RNE result, different committed raw.
        let mut reductions = Vec::new();
        let mut pending = Vec::new();
        for i in 0..2 {
            let (proof, claim) = prove_reduction(
                &statements[i],
                original[i],
                |cell| bytes(raw[i][cell]),
                &mut fs,
                &mut prows,
            )
            .unwrap();
            reductions.push(proof);
            pending.push(claim);
        }
        let byte_statements: Vec<_> =
            pending.iter().zip(&statements).map(|(p, s)| p.statement(s)).collect();
        let originals: Vec<_> = pending.iter().map(|p| p.aggregate).collect();
        let (joint, byte_point, byte) = batch::prove(
            &byte_statements,
            &originals,
            |i, j| {
                if statements[i].live(j / 8) && j % 8 < 6 {
                    bytes(raw[i][j / 8])[j % 8]
                } else {
                    0
                }
            },
            &mut fs,
            &mut prows,
        )
        .unwrap();
        let mut wire = Vec::new();
        joint.write(&mut wire);
        assert_eq!(wire.len(), batch::wire_bytes(d));
        for cut in [0, 4, wire.len() - 1] {
            assert!(batch::Proof::read(&mut &wire[..cut]).is_err());
        }
        let joint = batch::Proof::read(&mut wire.as_slice()).unwrap();
        let mut encoded = Vec::new();
        reductions.write(&mut encoded);
        let reductions = Vec::<Reduction>::read(&mut encoded.as_slice()).unwrap();
        let new_bytes = encoded.len() + wire.len();
        if fault == 0 {
            // Measure the existing prover's valid wire too, in an independent transcript.
            let old_count = 2 + required(2, 2) + required(1, 1);
            let mut old_rng = MatrixRng::from_seed([194; 32]);
            let mut old_rows = (0..old_count)
                .map(|_| Auth::new(from_p3(old_rng.random::<E>()), from_p3(old_rng.random::<E>())))
                .collect::<Vec<_>>()
                .into_iter();
            let mut old_fs = Fs::new(b"C71 independent unbatched byte measurement", 100_000);
            let (w, a) = range::authenticate(values, &mut old_rows);
            record_values(&mut old_fs, 0x74, &w);
            let mut proofs = Vec::new();
            for i in 0..2 {
                proofs.push(
                    prove(&statements[i], a[i], |j| bytes(raw[i][j]), &mut old_fs, &mut old_rows)
                        .unwrap()
                        .0,
                );
            }
            let mut old_wire = Vec::new();
            proofs.write(&mut old_wire);
            assert!(old_rows.next().is_none());
            assert_eq!(old_wire.len(), 4 + wire_bytes(2, 2) + wire_bytes(1, 1));
            assert!(new_bytes < old_wire.len());
            eprintln!("joint_RNE valid component bytes old={} new={new_bytes} saved={} joint={} correlations={count}",
                old_wire.len(), old_wire.len() - new_bytes, wire.len());
        }
        let forms_for = |point: Vec<Fp3>, ranges: [Vec<Cube>; 2]| {
            let mut forms = Vec::from(ranges);
            // Virtual packing is a public linear form in the SAME actual A.
            let raw_forms = (0..2)
                .map(|i| {
                    let local_bits = points[i].len() + 3;
                    let prefix_bits = point.len() - local_bits;
                    let coefficient =
                        point[..prefix_bits].iter().enumerate().fold(Fp3::ONE, |v, (j, &r)| {
                            v * if offsets[i] >> (point.len() - 1 - j) & 1 == 1 {
                                r
                            } else {
                                Fp3::ONE - r
                            }
                        });
                    Cube {
                        offset: 128 * (i + 1),
                        point: point[prefix_bits..].to_vec(),
                        coefficient,
                    }
                })
                .collect();
            forms.push(raw_forms);
            for i in 0..2 {
                let mut point = points[i].clone();
                point.push(signed(256) * signed(257).inv());
                forms.push(vec![Cube { offset: 64 + 8 * i, point, coefficient: signed(257) }]);
            }
            forms
        };
        let biases: [Fp3; 2] = std::array::from_fn(|i| {
            signed(32768) * byte_function::live_mass(outputs[i].len(), &points[i])
        });
        let (range_proof, ranges, targets) = range::prove(
            &model,
            attempt,
            [40; 32],
            272,
            range::Alphabet::Byte,
            &mut fs,
            &mut prows,
        )
        .unwrap();
        let targets = [
            targets[0],
            targets[1],
            byte,
            Auth::new(original[0].x + biases[0], original[0].m),
            Auth::new(original[1].x + biases[1], original[1].m),
        ];
        let (pcs, digest) = linear::prove(
            &model,
            attempt,
            [40; 32],
            &forms_for(byte_point, ranges),
            &targets,
            &mut fs,
            &mut prows,
        )
        .unwrap();
        assert!(prows.next().is_none());
        let mut fs = start();
        let mut vrows = keys.clone().into_iter();
        let original = range::correct(output_wire, delta, &mut vrows);
        record_values(&mut fs, 0x74, &output_wire);
        let checked: Result<Vec<_>, _> = (0..2)
            .map(|i| {
                verify_reduction(
                    &statements[i],
                    original[i],
                    &reductions[i],
                    delta,
                    &mut fs,
                    &mut vrows,
                )
            })
            .collect();
        if fault == 1 {
            assert!(checked.is_err());
            continue;
        }
        let mut pending = checked.unwrap();
        if fault == 3 {
            pending[0].aggregate[0].k += Fp3::ONE;
        }
        if fault == 5 {
            pending[0].tables[0][0] += Fp3::ONE;
        }
        let mut byte_statements: Vec<_> =
            pending.iter().zip(&statements).map(|(p, s)| p.statement(s)).collect();
        let mut originals: Vec<_> = pending.iter().map(|p| p.aggregate).collect();
        if fault == 4 {
            byte_statements.swap(0, 1);
            originals.swap(0, 1);
        }
        let checked =
            batch::verify(&byte_statements, &originals, &joint, delta, &mut fs, &mut vrows);
        if fault >= 3 {
            assert!(checked.is_err(), "fault {fault}");
            continue;
        }
        let (point, byte) = checked.unwrap();
        let (ranges, targets) = range::verify(
            n,
            &model.root,
            attempt,
            [40; 32],
            272,
            range::Alphabet::Byte,
            &range_proof,
            delta,
            &mut fs,
            &mut vrows,
        )
        .unwrap();
        let targets = [
            targets[0],
            targets[1],
            byte,
            Key::new(original[0].k + delta * biases[0]),
            Key::new(original[1].k + delta * biases[1]),
        ];
        let checked = linear::verify(
            n,
            &model.root,
            attempt,
            [40; 32],
            &forms_for(point, ranges),
            &targets,
            &pcs,
            delta,
            &mut fs,
            &mut vrows,
        );
        if fault == 2 {
            assert!(checked.is_err());
        } else {
            assert_eq!(checked.unwrap(), digest);
        }
        assert!(vrows.next().is_none());
    }
}

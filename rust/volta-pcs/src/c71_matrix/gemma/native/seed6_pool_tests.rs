use super::*;
use volta_pcg::{
    c71_lifetime::Lifetime,
    c71_seed6::{self, Geometry},
};

pub(in crate::c71_matrix::gemma::native) fn pair<ProverValue: Send, VerifierValue>(
    geometry: Geometry,
    binding: ModelBinding,
    prover: impl FnOnce(&mut ProverCapacity<'_, '_>) -> ProverValue + Send,
    verifier: impl FnOnce(&mut VerifierCapacity<'_, '_>) -> VerifierValue,
) -> (ProverValue, VerifierValue, (u64, u64), [u8; 32]) {
    let directory = std::env::temp_dir().join(format!(
        "c71-seed6-native-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let (prover_path, verifier_path) = (directory.join("prover"), directory.join("verifier"));
    let (prover_channel, verifier_channel) = std::os::unix::net::UnixStream::pair().unwrap();
    for channel in [&prover_channel, &verifier_channel] {
        channel.set_read_timeout(Some(std::time::Duration::from_secs(45))).unwrap();
        channel.set_write_timeout(Some(std::time::Duration::from_secs(45))).unwrap();
    }
    let output = std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let value = {
                let mut pool =
                    c71_seed6::prover(&mut store, prover_channel, [81; 32], [82; 32], geometry)
                        .unwrap();
                let mut capacity = ProverCapacity::Seed6(&mut pool);
                let value = prover(&mut capacity);
                capacity.stop();
                value
            };
            (value, store.counters(), store.accepted_head())
        });
        let mut store = Lifetime::install(&verifier_path, binding).unwrap();
        let value = {
            let mut pool =
                c71_seed6::verifier(&mut store, verifier_channel, [81; 32], [82; 32], geometry)
                    .unwrap();
            let mut capacity = VerifierCapacity::Seed6(&mut pool);
            let value = verifier(&mut capacity);
            capacity.stop();
            value
        };
        let (prover_value, counts, head) = peer.join().unwrap();
        assert_eq!(counts, store.counters());
        assert_eq!(head, store.accepted_head());
        (prover_value, value, counts, head)
    });
    for path in [prover_path, verifier_path] {
        assert!(Lifetime::open(&path, binding).is_err());
        std::fs::remove_file(path).unwrap();
    }
    std::fs::remove_dir(directory).unwrap();
    output
}

#[test]
fn c71_seed6_native_packing_reads_exact_triples_and_rejects_failure() {
    let base = [[7, 11, 13, 17], [19, 23, 29, 31], [37, 41, 43, 47]];
    let triple = read_triple(&mut base.iter().map(Ok));
    let packed = auth_triple(triple).unwrap();
    let dense = auths(&base).unwrap().next().unwrap();
    assert_eq!((packed.x, packed.m), (dense.x, dense.m));
    for fault in 0..3 {
        let outcome = std::panic::catch_unwind(|| {
            let mut rows = base.iter().enumerate().map(|(index, row)| {
                if index == fault {
                    Err(io_error("injected row failure".into()))
                } else {
                    Ok(row)
                }
            });
            read_triple(&mut rows)
        });
        assert!(outcome.is_err());
    }
    assert!(std::panic::catch_unwind(|| read_triple(&mut base[..2].iter().map(Ok))).is_err());
}

#[test]
fn c71_seed6_native_partial_lazy_consumption_burns_without_acceptance() {
    let binding = ModelBinding { anchor: [1; 32], root: [2; 32], semantics: [3; 32] };
    let (auth, (key, delta), counters, head) = pair(
        Geometry::new(2, 4, 2).unwrap(),
        binding,
        |pool| {
            let mut observed = None;
            assert!(pool
                .attempt::<()>(2, |_, rows| {
                    assert_eq!(rows.len(), 2);
                    observed = rows.next();
                    assert_eq!(rows.len(), 1);
                    Ok(((), Some([9; 32])))
                })
                .is_err());
            assert!(pool.fixed_run_context().is_err());
            assert_eq!(pool.remaining_fp3(), 0);
            assert!(pool.attempt::<()>(1, |_, _| panic!("reused partial attempt")).is_err());
            observed.unwrap()
        },
        |pool| {
            let mut observed = None;
            assert!(pool
                .attempt::<()>(2, |_, rows, delta| {
                    assert_eq!(rows.len(), 2);
                    observed = Some((rows.next().unwrap(), delta));
                    assert_eq!(rows.len(), 1);
                    Ok(((), Some([9; 32])))
                })
                .is_err());
            assert!(pool.fixed_run_context().is_err());
            assert!(pool.attempt::<()>(1, |_, _, _| panic!("reused partial attempt")).is_err());
            observed.unwrap()
        },
    );
    assert_eq!(key.k, auth.m + delta * auth.x);
    assert_eq!(counters, (1, 1));
    assert_eq!(head, [0; 32]);
}

#[test]
fn c71_seed6_native_shortage_stops_before_prepare_or_decode() {
    let profile = Profile::small(0).unwrap();
    let model = Installed::new(&profile, super::super::tests::weights(&profile)).unwrap();
    let root = model.root().clone();
    let binding =
        ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: profile.digest };
    let (_, _, counters, head) = pair(
        Geometry::new(2, 4, 2).unwrap(),
        binding,
        move |pool| {
            let mut prover: Prover<OrderedAux> = Prover::from_pool(model, pool).unwrap();
            assert!(prover
                .respond_with_pool(1, [83; 32], pool, |_| panic!("shortage emitted proof"))
                .is_err());
            assert!(prover.pending.is_none() && prover.accepted.is_empty() && !prover.state.live);
            assert_eq!(prover.state.cursor, 0);
            assert!(pool.fixed_run_context().is_err());
        },
        |pool| {
            let mut verifier = Verifier::from_pool(root, pool).unwrap();
            let response = Response {
                root: C61Commitment::new(vec![[98; 32]]),
                tokens: [1, 0],
                nonce: [83; 32],
                certificate: Vec::new(),
            };
            assert!(verifier.verify_with_pool(1, &response, pool).is_err());
            assert!(!verifier.state.live && verifier.state.accepted.is_empty());
            assert_eq!(verifier.state.cursor, 0);
            assert!(pool.fixed_run_context().is_err());
        },
    );
    assert_eq!(counters, (1, 0));
    assert_eq!(head, [0; 32]);
}

#[test]
fn c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals() {
    full_o0::<Snapshot>(false, 11, false);
}

#[test]
fn c71_seed6_native_full_o0_late_rejection_burns_without_promotion() {
    full_o0::<Snapshot>(true, 11, false);
}

#[test]
fn c71_seed6_native_ordered_o0_reduced_weight_complete_proof() {
    full_o0::<OrderedAux>(false, 2, false);
}

#[test]
fn c71_seed6_native_replay_w_and_ordered_a_complete_o0_proof() {
    full_o0::<OrderedAux>(false, 2, true);
}

#[test]
#[ignore = "three-response CPU run exceeded 60 s after two accepts; no multi-three credit"]
fn c71_seed6_native_three_retained_dense_responses_same_registry() {
    retained_responses(3);
}

#[test]
fn c71_seed6_native_two_retained_dense_responses_same_registry() {
    retained_responses(2);
}

fn retained_responses(count: usize) {
    // Full reduced numerical/proof schedule with real correlations. Dense tiny
    // snapshots keep this a CPU integration check, not canonical getter credit.
    let profile = Profile::small(0).unwrap();
    let model = Installed::new(&profile, super::super::tests::weights(&profile)).unwrap();
    let root = model.root().clone();
    let binding =
        ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: profile.digest };
    let (send, receive) = std::sync::mpsc::sync_channel(0);
    let (reply, replies) = std::sync::mpsc::sync_channel(0);
    let (prover_head, verifier_head, counters, head) = pair(
        Geometry::new(8, 19, 2).unwrap(),
        binding,
        move |pool| {
            let mut prover: Prover<Snapshot> = Prover::from_pool(model, pool).unwrap();
            for slot in 0..count {
                prover
                    .respond_authenticated(1, [83 + slot as u8; 32], pool, |response| {
                        send.send(response.clone()).map_err(|e| e.to_string())?;
                        replies
                            .recv_timeout(std::time::Duration::from_secs(45))
                            .map_err(|e| e.to_string())
                    })
                    .unwrap();
                assert_eq!(prover.accepted.len(), slot + 1);
                assert!(prover.pending.is_none());
            }
            assert_eq!(prover.state.live, count < 3);
            prover.state.accepted.last().unwrap().receipt
        },
        |pool| {
            let mut verifier = Verifier::from_pool(root, pool).unwrap();
            for slot in 0..count {
                let response = receive.recv_timeout(std::time::Duration::from_secs(45)).unwrap();
                let mut completion = Vec::new();
                let accepted = verifier.verify_authenticated(1, &response, pool, &mut completion);
                assert!(accepted.is_ok());
                assert_eq!(verifier.state.accepted.len(), slot + 1);
                reply.send(completion).unwrap();
                eprintln!(
                    "C71_REAL_REDUCED accepted={} bytes={} canonical=false credit=false",
                    slot + 1,
                    response.certificate.len()
                );
            }
            assert_eq!(verifier.state.live, count < 3);
            verifier.state.accepted.last().unwrap().receipt
        },
    );
    assert_eq!(prover_head, verifier_head);
    assert_eq!(head, verifier_head);
    assert_eq!(counters, (1, count as u64));
}

fn full_o0<Source: Auxiliary>(reject: bool, weight: usize, replay_weights: bool) {
    let profile = Arc::new(Profile::small(0).unwrap());
    let packed = super::super::tests::weights(&profile);
    let model = if replay_weights {
        Installed::new_sourcewise(profile.clone(), packed)
    } else {
        Installed::new(&profile, packed)
    }
    .unwrap();
    let root = model.root().clone();
    let binding =
        ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: profile.digest };
    let (response_sender, response_receiver) = std::sync::mpsc::sync_channel(0);
    let (acceptance_sender, acceptance_receiver) = std::sync::mpsc::sync_channel(0);
    let (prover_receipt, (verifier_receipt, bytes), counters, head) = pair(
        Geometry::new(4, 19, weight).unwrap(),
        binding,
        move |pool| {
            let mut prover: Prover<Source> = Prover::from_pool(model, pool).unwrap();
            let result = prover.respond_with_pool(1, [83; 32], pool, |response| {
                response_sender.send(response.clone()).unwrap();
                acceptance_receiver.recv_timeout(std::time::Duration::from_secs(45)).unwrap()
            });
            assert_eq!(result.is_err(), reject);
            assert!(prover.pending.is_none());
            assert_eq!(prover.accepted.len(), usize::from(!reject));
            assert_eq!(prover.state.cursor, 264147);
            let receipt = prover.state.accepted.first().map(|accepted| accepted.receipt);
            if reject {
                assert!(!prover.state.live && pool.fixed_run_context().is_err());
            } else {
                assert_eq!(pool.fixed_run_context().unwrap().2.predecessor, receipt.unwrap());
            }
            receipt
        },
        |pool| {
            let mut verifier = Verifier::from_pool(root, pool).unwrap();
            let mut response =
                response_receiver.recv_timeout(std::time::Duration::from_secs(45)).unwrap();
            if reject {
                *response.certificate.last_mut().unwrap() ^= 1;
            }
            let acceptance = verifier.verify_with_pool(1, &response, pool);
            assert_eq!(acceptance.is_err(), reject);
            let receipt = acceptance.as_ref().ok().map(|accepted| accepted.receipt);
            assert_eq!(verifier.state.accepted.len(), usize::from(!reject));
            assert_eq!(verifier.state.cursor, 264147);
            if reject {
                assert!(!verifier.state.live && pool.fixed_run_context().is_err());
            } else {
                assert_eq!(pool.fixed_run_context().unwrap().2.predecessor, receipt.unwrap());
            }
            acceptance_sender.send(acceptance).unwrap();
            (receipt, response.certificate.len())
        },
    );
    assert_eq!(prover_receipt, verifier_receipt);
    assert_eq!(head, prover_receipt.unwrap_or([0; 32]));
    assert_eq!(counters, (1, 1));
    println!(
        "C71_SEED6_NATIVE {}",
        serde_json::json!({
            "credit":false,"blocks":4,"height":19,"weight":weight,
            "base_rows":264147,"original_mac_rows":88049,"certificate_bytes":bytes,
            "receipt":head,"accepted_attempts":usize::from(!reject),"OS_rng":true,
            "late_rejection":reject,
            "source":std::any::type_name::<Source>(),
            "dense_virtual_W_materialized":!replay_weights,
            "scope":"one complete reduced O0 proof, optionally corrupted completion; real Seed6 bounded batches at the reported reduced geometry; not canonical security, H100 or full fixed-run credit"
        })
    );
}

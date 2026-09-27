#![cfg(feature = "c71-seed6-reference")]

use std::{os::unix::net::UnixStream, path::PathBuf, thread, time::Duration};
use volta_field::{Fp, Fp3};
use volta_pcg::{
    c71_lifetime::{Lifetime, ModelBinding},
    c71_seed6::{self, Geometry},
    c7_fp3::{
        c7_fp3_transfer_prover, c7_fp3_transfer_verifier, C7Fp3ProverAuthed, C7Fp3VerifierKey,
    },
};

fn path(role: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "c71-seed6-public-{role}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}

fn model() -> ModelBinding {
    ModelBinding { anchor: [1; 32], semantics: [2; 32], root: [3; 32] }
}

fn field(words: [u64; 3]) -> Fp3 {
    Fp3::new(Fp::new(words[0]), Fp::new(words[1]), Fp::new(words[2]))
}

#[test]
fn public_seed6_reference_has_owned_role_pools_and_original_fp3_transfer() {
    assert!(Geometry::new(0, 4, 2).is_err());
    assert!(Geometry::new(2, 20, 2).is_err());
    assert!(Geometry::new(1, 5, 2).is_ok());
    assert!(Geometry::new(1, 6, 2).is_ok());
    assert!(Geometry::new(1, 3, 2).is_err());
    let geometry = Geometry::new(2, 4, 2).unwrap();
    assert_eq!(geometry.capacity().unwrap(), 6);
    let (left, right) = UnixStream::pair().unwrap();
    for channel in [&left, &right] {
        channel.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
        channel.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
    }
    let target = field([17, 19, 23]);
    let peer = thread::spawn(move || {
        let path = path("prover");
        let mut store = Lifetime::install(&path, model()).unwrap();
        let output = {
            let mut pool =
                c71_seed6::prover(&mut store, right, [4; 32], [5; 32], geometry).unwrap();
            assert_eq!(pool.remaining_fp3(), 2);
            assert!(pool.fixed_run_context().unwrap().0 == model());
            assert_eq!(pool.audits().len(), 3);
            let output = pool
                .attempt(1, |attempt, rows| {
                    assert_eq!(attempt.first_base_row, 0);
                    let mut value = Fp3::ZERO;
                    let mut tag = Fp3::ZERO;
                    for basis in [Fp3::ONE, field([0, 1, 0]), field([0, 0, 1])] {
                        let row = rows.next().unwrap()?;
                        value += basis.mul_base(Fp::new(row[0]));
                        tag += basis * field([row[1], row[2], row[3]]);
                    }
                    assert!(rows.next().is_none());
                    Ok((
                        c7_fp3_transfer_prover(C7Fp3ProverAuthed::new(value, tag), target),
                        Some([9; 32]),
                    ))
                })
                .unwrap();
            assert_eq!(pool.remaining_fp3(), 1);
            assert_eq!(pool.fixed_run_context().unwrap().2.predecessor, [9; 32]);
            pool.stop();
            assert_eq!(pool.remaining_fp3(), 0);
            assert!(pool.fixed_run_context().is_err());
            output
        };
        drop(store);
        assert!(Lifetime::open(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
        output
    });
    let path = path("verifier");
    let mut store = Lifetime::install(&path, model()).unwrap();
    {
        let mut pool = c71_seed6::verifier(&mut store, left, [4; 32], [5; 32], geometry).unwrap();
        let (correction, authenticated) = peer.join().unwrap();
        pool.attempt(1, |attempt, rows, delta| {
            assert_eq!(attempt.first_base_row, 0);
            let mut key = Fp3::ZERO;
            for basis in [Fp3::ONE, field([0, 1, 0]), field([0, 0, 1])] {
                key += basis * field(*rows.next().unwrap()?);
            }
            assert!(rows.next().is_none());
            let native_delta = Fp3::ZERO - delta;
            let key =
                c7_fp3_transfer_verifier(C7Fp3VerifierKey::new(key), native_delta, correction);
            assert_eq!(key.k, authenticated.m + native_delta * target);
            Ok(((), Some([9; 32])))
        })
        .unwrap();
        pool.stop();
        assert!(pool.attempt::<()>(1, |_, _, _| panic!("stopped pool used")).is_err());
    }
    drop(store);
    assert!(Lifetime::open(&path, model()).is_err());
    std::fs::remove_file(path).unwrap();
    println!("C71_SEED6_PUBLIC external_crate=true OS_rng=true original_fp3_transfer=true acceptance_fixture=true proof=false production=false");
}

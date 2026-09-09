//! Opt-in B12 unique-radius IOP and salted consumer. The hash/FS/lifetime
//! compilation remains a separate obligation; this is not production admission.

use super::*;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};

/// Theorem 9.10 code switches, terminated by Theorem 8.1's masked fold/base
/// case. Only creates a small configuration; callers keep the D14 CPU cap.
pub(super) fn config(h: usize) -> Result<ZkWhirConfig<E, Goldilocks, Fs>, String> {
    if !(10..=35).contains(&h) {
        return Err("B12 configuration domain must be D10..D35".into());
    }
    let strategy = FoldingFactor::ConstantFromSecondRound(if h <= 14 { 1 } else { 7 }, 2);
    let folds = strategy.compute_folding_schedule(h).map_err(|e| e.to_string())?;
    let (mut remaining, mut rates) = (h, Vec::new());
    for (i, &folding) in folds.iter().enumerate() {
        remaining -= folding;
        let message = 1usize << remaining;
        let randomness = if i == 0 { 1536 } else { 512 };
        let domain = (8 * (message + randomness)).next_power_of_two();
        if domain > 1usize << 32 {
            return Err("B12 folded domain exceeds Goldilocks two-adicity".into());
        }
        rates.push(domain.ilog2() as usize - remaining);
    }
    let mut result = ZkWhirConfig::new(
        h,
        ProtocolParameters {
            security_level: 128, // constructor only; the exact RBR bound is in the B12 design
            pow_bits: 0,
            starting_log_inv_rate: rates[0],
            round_log_inv_rates: rates[1..].to_vec(),
            folding_factor: strategy,
            soundness_type: SecurityAssumption::JohnsonBound,
        },
        ZkParameters { ell_zk: 2048, mask_log_inv_rate: 3 },
    )
    .map_err(|e| e.to_string())?;
    result.mask_queries = 512;
    result.oracle_randomness.fill(512);
    result.oracle_randomness[0] = 1536;
    result.sumcheck_mask = MaskCodeShape::new(2048, 512, 3);
    result.switch_masks.fill(result.sumcheck_mask);
    for round in &mut result.inner.round_parameters {
        round.num_queries = 512;
        round.ood_samples = 1; // one nonzero point hides with one free pad coefficient
    }
    result.inner.final_queries = 512;
    Ok(result)
}

/// Private coins in the same classical XOF-ROM as C71FS, under a separate
/// domain. No Clone: an MMCS clone draws a new secret seed. Recreating a
/// fixed model intentionally repeats its coins, within the root's slots.
pub(super) struct PrivateRng {
    reader: blake3::OutputReader,
    remaining: u64,
}

impl SeedableRng for PrivateRng {
    type Seed = [u8; 32];
    fn from_seed(seed: Self::Seed) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(b"volta-zk/c71/b12/private-coins/v1\0");
        hash.update(&seed);
        Self { reader: hash.finalize_xof(), remaining: 1 << 40 }
    }
}

impl rand_010::TryRng for PrivateRng {
    type Error = std::convert::Infallible;
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .expect("B12 private coin stream exhausted; burn the attempt");
        self.reader.fill(bytes);
        Ok(())
    }
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl rand_010::TryCryptoRng for PrivateRng {}

#[derive(Clone, Debug)]
pub(super) struct DomainHash(&'static [u8]);

impl CryptographicHasher<u8, [u8; 32]> for DomainHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        p3_blake3::Blake3.hash_iter(self.0.iter().copied().chain(input))
    }
}

pub(super) type HidingMmcs = MerkleTreeHidingMmcs<
    Goldilocks,
    u8,
    SerializingHasher<DomainHash>,
    CompressionFunctionFromHasher<DomainHash, 2, 32>,
    PrivateRng,
    2,
    32,
    4,
>;

pub(super) fn mmcs(seed: [u8; 32]) -> HidingMmcs {
    HidingMmcs::new(
        SerializingHasher::new(DomainHash(b"volta-zk/c71/b12/merkle/leaf/v1\0")),
        CompressionFunctionFromHasher::new(DomainHash(b"volta-zk/c71/b12/merkle/node/v1\0")),
        0,
        PrivateRng::from_seed(seed),
    )
}

pub(super) fn bind_salts(bytes: &mut Vec<u8>, salts: &[Vec<Vec<Goldilocks>>]) {
    bytes.extend_from_slice(&(salts.len() as u32).to_le_bytes());
    for matrices in salts {
        bytes.extend_from_slice(&(matrices.len() as u32).to_le_bytes());
        for row in matrices {
            bytes.extend_from_slice(&(row.len() as u32).to_le_bytes());
            for salt in row {
                bytes.extend_from_slice(&salt.as_canonical_u64().to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_commit::Mmcs;
    use p3_matrix::{dense::RowMajorMatrix, Dimensions};

    #[test]
    fn c71_b12_fs_uses_one_tape_across_draws_and_fixed_openings() {
        // Independent flat transcript and one XOF response, including every
        // request/result frame; no calls to Fs's framing or request helpers.
        fn frame(bytes: &mut Vec<u8>, event: u64, kind: u16, body: &[u8]) {
            bytes.extend(event.to_le_bytes());
            bytes.extend(0u16.to_le_bytes());
            bytes.extend(kind.to_le_bytes());
            bytes.extend((body.len() as u64).to_le_bytes());
            bytes.extend(body);
        }
        fn request(counter: u64, kind: u16, width: u32) -> Vec<u8> {
            [
                counter.to_le_bytes().as_slice(),
                &kind.to_le_bytes(),
                &width.to_le_bytes(),
                &8u32.to_le_bytes(),
            ]
            .concat()
        }
        let statement = b"B12 coin-block XOF known answer";
        let mut bytes = b"volta-zk/c7.1/fs/v1".to_vec();
        frame(&mut bytes, 0, 0, statement);
        frame(&mut bytes, 1, 0xff00, &request(0, 2, 11));
        let mut tape = blake3::Hasher::new();
        tape.update(&bytes);
        let mut tape = tape.finalize_xof();
        let mut fs = Fs::new(statement, 515);
        for i in 0..512u64 {
            if i != 0 {
                frame(&mut bytes, 2 * i + 1, 0xff00, &request(i, 2, 11));
            }
            let mut word = [0; 8];
            tape.fill(&mut word);
            let index = u64::from_le_bytes(word) & 2047;
            assert_eq!(fs.sample_bits(11), index as usize);
            frame(&mut bytes, 2 * i + 2, 0xff01, &index.to_le_bytes());
        }
        assert_eq!(fs.digest(), blake3::hash(&bytes));
        assert_eq!(fs.0.lock().unwrap().coin_tape.as_ref().unwrap().position(), 512 * 8);
        // Authenticated openings are fixed by prior roots; retain this tape.
        frame(&mut bytes, 1025, 0x2100, b"fixed opening");
        frame(&mut bytes, 1026, 0xff00, &request(512, 2, 11));
        let mut word = [0; 8];
        tape.fill(&mut word);
        let index = u64::from_le_bytes(word) & 2047;
        fs.record(0x2100, b"fixed opening");
        assert_eq!(fs.sample_bits(11), index as usize);
        frame(&mut bytes, 1027, 0xff01, &index.to_le_bytes());
        // A fresh prover message must close the tape and bind every prior frame.
        frame(&mut bytes, 1028, 1, &7u64.to_le_bytes());
        frame(&mut bytes, 1029, 0xff00, &request(513, 1, 3));
        let mut next = blake3::Hasher::new();
        next.update(&bytes);
        let mut next = next.finalize_xof();
        let mut raw = [0; 24];
        next.fill(&mut raw);
        let expected = Fp3::from_bytes(&raw).unwrap(); // this fixed tape has no rejection
        fs.observe(Goldilocks::new(7));
        assert_eq!(fs.fp3(), expected);
        frame(&mut bytes, 1030, 0xff01, &raw);
        let mut word = [0; 8];
        next.fill(&mut word);
        let index = u64::from_le_bytes(word) & 2047;
        let mut replay = fs.fork();
        assert_eq!(fs.sample_bits(11), index as usize);
        assert_eq!(replay.sample_bits(11), index as usize);
        frame(&mut bytes, 1031, 0xff00, &request(514, 2, 11));
        frame(&mut bytes, 1032, 0xff01, &index.to_le_bytes());
        assert_eq!(fs.digest(), blake3::hash(&bytes));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fs.fp3())).is_err());
    }

    #[test]
    fn c71_b12_native_codes_have_unique_radius_and_common_private_masks() {
        for h in [10, 12, 14, 35] {
            let c = config(h).unwrap();
            assert_eq!(c.max_pow_bits(), 0);
            assert_eq!(c.final_sumcheck_rounds, if h == 35 { 6 } else { 5 });
            assert_eq!(c.mask_queries, 512);
            assert!(c.mask_groups().iter().all(|g| g.shape == c.sumcheck_mask));
            assert_eq!(c.sumcheck_mask, MaskCodeShape::new(2048, 512, 3));
            let mut previous_domain = usize::MAX;
            for (i, r) in c
                .round_parameters
                .iter()
                .chain(std::iter::once(&c.final_round_config()))
                .enumerate()
            {
                let message = 1usize << r.num_variables;
                let domain = r.domain_size >> r.folding_factor;
                let dimension = message + c.oracle_randomness[i];
                assert!(3 * (domain / 4) < domain - dimension + 1);
                assert_eq!(domain, (8 * dimension).next_power_of_two());
                assert!(domain <= 1usize << 32 && r.domain_size <= previous_domain);
                assert_eq!(r.num_queries, 512);
                assert!(c.zk.ell_zk > c.oracle_randomness[i]);
                previous_domain = r.domain_size;
            }
            assert_eq!(c.oracle_randomness[0], 3 * 512);
            if let Some(expected) = [(12, 2_883_618), (14, 3_670_058), (35, 9_175_151)]
                .into_iter()
                .find_map(|(dimension, cap)| (h == dimension).then_some(cap))
            {
                assert_eq!(request_limit(&c), expected);
            }
            if h == 35 {
                assert_eq!(8 * c.starting_domain_size(), 4usize << 40);
                assert!(super::super::config(h).is_err()); // never allocate this on the CPU path
            }
        }
    }

    #[test]
    fn c71_b12_private_coins_replay_stream_and_fail_closed() {
        use rand_010::Rng;
        let seed = [3; 32];
        let mut rng = PrivateRng::from_seed(seed);
        let mut whole = [0; 257];
        rng.fill_bytes(&mut whole);
        let mut expected = [0; 257];
        let mut hash = blake3::Hasher::new();
        hash.update(b"volta-zk/c71/b12/private-coins/v1\0");
        hash.update(&seed);
        hash.finalize_xof().fill(&mut expected);
        assert_eq!(whole, expected);
        let mut split = PrivateRng::from_seed(seed);
        assert_eq!(split.next_u32().to_le_bytes(), whole[..4]);
        assert_eq!(split.next_u64().to_le_bytes(), whole[4..12]);
        split.fill_bytes(&mut expected[12..]);
        assert_eq!(expected[12..], whole[12..]);
        assert_eq!(split.remaining, (1 << 40) - 257);
        split.remaining = 0;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| split.next_u64())).is_err()
        );
    }

    #[test]
    fn c71_b12_salted_merkle_replays_and_rejects_salt_changes() {
        assert!(super::super::preflight(48).is_err()); // cannot select the stopped B7 bootstrap
        let matrix = RowMajorMatrix::new((0..16).map(Goldilocks::new).collect(), 2);
        let a = mmcs([1; 32]);
        let (root, data) = a.commit_matrix(matrix.clone());
        assert_eq!(root, mmcs([1; 32]).commit_matrix(matrix.clone()).0);
        assert_ne!(root, a.clone().commit_matrix(matrix.clone()).0);
        assert_ne!(root, mmcs([2; 32]).commit_matrix(matrix).0);
        let (rows, proof) = a.open_multi_batch(&[1, 3], &data);
        let dimensions = [Dimensions { height: 8, width: 2 }];
        a.verify_multi_batch(&root, &dimensions, &[1, 3], &rows, &proof).unwrap();
        for truncate in [false, true] {
            let mut bad = proof.clone();
            if truncate {
                bad.0[0][0].pop();
            } else {
                bad.0[0][0][0] += Goldilocks::ONE;
            }
            assert!(a.verify_multi_batch(&root, &dimensions, &[1, 3], &rows, &bad).is_err());
        }
        // A raw 64-byte input cannot cross leaf/node domains.
        let leaf = DomainHash(b"volta-zk/c71/b12/merkle/leaf/v1\0");
        let node = DomainHash(b"volta-zk/c71/b12/merkle/node/v1\0");
        assert_ne!(leaf.hash_slice(&[0; 64]), node.hash_slice(&[0; 64]));
        assert_eq!(
            leaf.hash_slice(&[0; 64]),
            *blake3::hash(&[leaf.0, &[0; 64]].concat()).as_bytes()
        );
        let fs = Fs::new(b"salt transcript", 0);
        let changed_fs = fs.fork();
        let observe = ObservedMmcs::new(fs.clone(), [0; 32]);
        observe.bind(&[1, 3], &rows, &proof);
        let mut changed = proof.clone();
        changed.0[0][0][0] += Goldilocks::ONE;
        ObservedMmcs::new(changed_fs.clone(), [0; 32]).bind(&[1, 3], &rows, &changed);
        assert_ne!(fs.digest(), changed_fs.digest());
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_real_durable_roles_bind_matrix_to_one_salted_root() {
        use std::io::{self, Read, Write};
        use volta_pcg::c71_lifetime::{Attempt, Lifetime, ModelBinding};
        let n = 48;
        let model = Model::new(n, (0..n * n).map(|i| (i % 19) as i16 - 9).collect()).unwrap();
        let root = model.root.clone();
        let config = matrix_config(n).unwrap();
        let mut semantics = gamma(&config);
        semantics.extend_from_slice(&(n as u32).to_le_bytes());
        let binding = ModelBinding {
            anchor: root.roots()[0],
            root: root.roots()[0],
            semantics: *blake3::hash(&semantics).as_bytes(),
        };
        let required = 3 * (config.num_variables / 2) + 2;
        let input: Vec<_> = (0..n).map(|i| (i % 7) as i16 - 3).collect();
        let output: Vec<_> = model
            .weights
            .chunks_exact(n)
            .map(|row| {
                row.iter().zip(&input).map(|(&w, &x)| i64::from(w) * i64::from(x)).sum::<i64>()
            })
            .collect();
        let prover_input = input.clone();
        let prover_output = output.clone();
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-b12-pcs-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ppath = directory.join("prover");
        let vpath = directory.join("verifier");
        let prover_path = ppath.clone();
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let context = |a: &Attempt| {
            let mut hash = blake3::Hasher::new();
            hash.update(b"volta-zk/c71/b12/test-attempt/v1");
            hash.update(&a.capacity);
            hash.update(&a.ordinal.to_le_bytes());
            hash.update(&a.predecessor);
            AttemptContext {
                session: [4; 32],
                capacity: a.capacity,
                slot: (a.ordinal - 1) as u8,
                predecessor: a.predecessor,
                nonce: *hash.finalize().as_bytes(),
            }
        };
        let io_error = |e: String| io::Error::new(io::ErrorKind::InvalidData, e);
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for channel in [&pc, &vc] {
            channel.set_read_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
            channel.set_write_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
        }
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let mut pool = store.prover(&mut pc, [4; 32], [5; 32], 9 * required).unwrap();
            let mut scratch_roots = Vec::new();
            for slot in 0..3 {
                pool.attempt(required, |a, rows, _| {
                    let mut auths = rows
                        .chunks_exact(3)
                        .map(|r| {
                            let tag = |row: [u64; 4]| field([row[1], row[2], row[3]]);
                            Auth::new(
                                field([r[0][0], r[1][0], r[2][0]]),
                                tag(r[0]) + u * tag(r[1]) + u * u * tag(r[2]),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_iter();
                    let attempt = context(&a);
                    let (mut proof, digest) =
                        matrix_prove(&model, &prover_input, &prover_output, attempt, &mut auths)
                            .map_err(io_error)?;
                    assert!(auths.next().is_none());
                    scratch_roots.push(proof.pcs.sumcheck_mask_commitments[0].clone());
                    if slot == 2 {
                        // A fresh burned attempt contains the deliberately invalid salt.
                        match &mut proof.pcs.rounds[0].openings {
                            p3_whir_c61::pcs::proof::QueryOpenings::Base(o) => {
                                o.proof.0[0][0][0] += Goldilocks::ONE
                            }
                            _ => unreachable!(),
                        }
                    }
                    let bytes = codec::encode(
                        n,
                        &model.root,
                        &prover_input,
                        &prover_output,
                        attempt,
                        &proof,
                    )
                    .map_err(|e| io_error(e.to_string()))?;
                    pc.write_all(&(bytes.len() as u32).to_le_bytes())?;
                    pc.write_all(&bytes)?;
                    let mut ack = [0; 32];
                    pc.read_exact(&mut ack)?;
                    if slot < 2 {
                        assert_eq!(ack, *digest.as_bytes());
                    } else {
                        assert_eq!(ack, [0; 32]);
                    }
                    Ok(((), (ack != [0; 32]).then_some(ack)))
                })
                .unwrap();
            }
            assert!(scratch_roots.windows(2).all(|r| r[0] != r[1]));
            assert!(pool
                .attempt::<()>(required, |_, _, _| panic!("exhausted pool called consumer"))
                .is_err());
        });
        let mut accepted = [0; 32];
        {
            let mut store = Lifetime::install(&vpath, binding).unwrap();
            let mut pool = store.verifier(&mut vc, [4; 32], [5; 32], 9 * required).unwrap();
            for slot in 0..3 {
                let head = pool
                    .attempt(required, |a, rows, delta| {
                        assert_eq!(a.predecessor, accepted);
                        let keys = rows
                            .chunks_exact(3)
                            .map(|r| Key::new(field(r[0]) + u * field(r[1]) + u * u * field(r[2])))
                            .collect::<Vec<_>>();
                        let native_delta = Fp3::ZERO - field(*delta.unwrap());
                        let attempt = context(&a);
                        let mut length = [0; 4];
                        vc.read_exact(&mut length)?;
                        let length = u32::from_le_bytes(length) as usize;
                        assert!(length <= codec::MAX_BYTES);
                        let mut bytes = vec![0; length];
                        vc.read_exact(&mut bytes)?;
                        let proof = codec::decode(n, &root, &input, &output, attempt, &bytes)
                            .map_err(|e| io_error(e.to_string()))?;
                        assert_eq!(codec::encode(n, &root, &input, &output, attempt, &proof)
                            .unwrap(), bytes);
                        let first_salt: Vec<u8> = match &proof.pcs.rounds[0].openings {
                            p3_whir_c61::pcs::proof::QueryOpenings::Base(o) => o.proof.0[0][0]
                                .iter().flat_map(|s| s.as_canonical_u64().to_le_bytes()).collect(),
                            _ => unreachable!(),
                        };
                        let offsets: Vec<_> = bytes.windows(first_salt.len()).enumerate()
                            .filter_map(|(i, w)| (w == first_salt).then_some(i)).collect();
                        assert_eq!(offsets.len(), 1);
                        let mut noncanonical = bytes.clone();
                        noncanonical[offsets[0]..offsets[0]+8].copy_from_slice(&volta_field::P.to_le_bytes());
                        assert!(codec::decode(n, &root, &input, &output, attempt, &noncanonical).is_err());
                        let mut legacy = bytes.clone();
                        legacy[..8].copy_from_slice(b"C71MX1\0\0");
                        assert!(codec::decode(n, &root, &input, &output, attempt, &legacy).is_err());
                        // Wrong W/root and wrong public output cannot reuse this certificate.
                        let wrong_root = C61Commitment::new(vec![[7; 32]]);
                        assert!(codec::decode(n, &wrong_root, &input, &output, attempt, &bytes)
                            .is_err());
                        let mut wrong_output = output.clone();
                        wrong_output[0] += 1;
                        assert!(matrix_verify(
                            n,
                            &root,
                            &input,
                            &wrong_output,
                            attempt,
                            &proof,
                            native_delta,
                            &mut keys.clone().into_iter()
                        )
                        .is_err());
                        let mut keys = keys.into_iter();
                        let checked = matrix_verify(
                            n,
                            &root,
                            &input,
                            &output,
                            attempt,
                            &proof,
                            native_delta,
                            &mut keys,
                        );
                        let head = if slot < 2 {
                            let digest = checked.map_err(io_error)?;
                            assert!(keys.next().is_none());
                            accepted = *digest.as_bytes();
                            Some(accepted)
                        } else {
                            assert!(checked.is_err());
                            None
                        };
                        Ok((head, head))
                    })
                    .unwrap();
                // Ack only after the verifier's accepted head has been synced.
                vc.write_all(&head.unwrap_or([0; 32])).unwrap();
            }
        }
        prover.join().unwrap();
        for path in [ppath, vpath] {
            let store = Lifetime::open(&path, binding).unwrap();
            assert_eq!(store.counters(), (1, 3));
            assert_eq!(store.accepted_head(), accepted);
            drop(store);
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}

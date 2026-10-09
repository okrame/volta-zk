//! Opt-in B12 unique-radius IOP and salted consumer. The hash/FS/lifetime
//! compilation remains a separate obligation; this is not production admission.

use super::*;
mod streaming;
mod sourcewise;
mod replay_tree;
pub(super) mod replay;

use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};

/// Theorem 9.10 code switches, terminated by Theorem 8.1's masked fold/base
/// case. This only creates a small configuration. The matrix diagnostic keeps
/// its D14 cap; larger flat sources have no physical-schedule admission.
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
    // Original private input, retained for exact device XOF reconstruction.
    // It is never exposed to the numeric producer or serialized in telemetry.
    seed: [u8; 32],
    remaining: u64,
    // Only sequential samplers buffer. Strided leaf replay uses the same XOF
    // at its logical cursor without allocating/refilling 4 KiB for 32 bytes.
    buffer: Option<Box<[u8; 4096]>>,
    cursor: usize,
}

impl SeedableRng for PrivateRng {
    type Seed = [u8; 32];
    fn from_seed(seed: Self::Seed) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(b"volta-zk/c71/b12/private-coins/v1\0");
        hash.update(&seed);
        Self { reader: hash.finalize_xof(), seed, remaining: 1 << 40,
            buffer: Some(Box::new([0; 4096])), cursor: 4096 }
    }
}

impl PrivateRng {
    // Replay only the same committed oracle, from a recorded sampler offset.
    // No new root/session may use a replayed private stream.
    fn replay_at(seed: [u8;32], offset: u64) -> Result<Self, String> {
        if offset >= 1 << 40 { return Err("private coin offset exhausted".into()); }
        let mut rng=Self::from_seed(seed);
        rng.remaining=rng.remaining.checked_sub(offset).ok_or("private coin offset exceeds cap")?;
        rng.reader.set_position(offset);
        Ok(rng)
    }
    fn position(&self) -> u64 { (1 << 40)-self.remaining }

    // Exact device prescan consumes the live stream once. Discard the host
    // prefetch while keeping its already charged buffer for later fresh draws.
    fn advance_to(&mut self, end: u64) -> Result<u64, String> {
        let start = self.position();
        if end < start || end > 1 << 40 { return Err("private coin advance outside live stream".into()); }
        self.reader.set_position(end); self.remaining = (1 << 40) - end; self.cursor = 4096;
        Ok(end - start)
    }

    fn snapshot_at(&self, offset: u64) -> Result<Self, String> {
        if offset >= 1 << 40 { return Err("private coin offset exhausted".into()); }
        let mut reader = self.reader.clone();
        reader.set_position(offset); // reader.position() can be ahead of the logical cursor
        Ok(Self { reader, seed: self.seed, remaining: (1 << 40) - offset, buffer: None, cursor: 4096 })
    }

    /// The same four StandardUniform Goldilocks samples, in candidate order.
    /// A short XOF fill recomputes its 64-byte block; batch only candidates
    /// still needed, without consuming a word beyond the fourth accepted salt.
    fn salts4(&mut self) -> [Goldilocks; 4] {
        use rand_010::Rng;
        let mut salts = [Goldilocks::ZERO; 4];
        let mut accepted = 0;
        let mut bytes = [0; 32];
        while accepted < salts.len() {
            // Exhaust whole candidates first. With fewer than eight bytes
            // left the ordinary read panics at the same cursor as random().
            let count = (salts.len() - accepted).min((self.remaining / 8) as usize).max(1);
            self.fill_bytes(&mut bytes[..8 * count]);
            for word in bytes[..8 * count].chunks_exact(8) {
                let candidate = u64::from_le_bytes(word.try_into().unwrap());
                if candidate < Goldilocks::ORDER_U64 {
                    salts[accepted] = Goldilocks::new(candidate);
                    accepted += 1;
                }
            }
        }
        salts
    }
}

impl rand_010::TryRng for PrivateRng {
    type Error = std::convert::Infallible;
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .expect("B12 private coin stream exhausted; burn the attempt");
        let Some(buffer) = self.buffer.as_mut() else {
            self.reader.fill(bytes);
            return Ok(());
        };
        let mut output = bytes;
        while !output.is_empty() {
            if self.cursor == buffer.len() {
                if output.len() >= buffer.len() {
                    self.reader.fill(output);
                    break;
                }
                // Never prefetch beyond the finite stream, including on a
                // partial last refill. Only requested bytes consume capacity.
                let available = ((1u64 << 40) - self.reader.position()).min(buffer.len() as u64);
                self.cursor = buffer.len() - available as usize;
                self.reader.fill(&mut buffer[self.cursor..]);
            }
            let count = output.len().min(buffer.len() - self.cursor);
            output[..count].copy_from_slice(&buffer[self.cursor..self.cursor + count]);
            self.cursor += count;
            output = &mut output[count..];
        }
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
    fn c71_b12_designated_verifier_state_simulates_with_a_zero_weight_pcs() {
        use rand_010::RngExt;
        // Constructive ideal-MAC simulator: it receives Delta/keys and public
        // IO, NEVER a private inference witness. These secrets are unavailable
        // to a malicious prover; this is not a soundness attack or a bootstrap.
        // Acceptance alone is not a distributional ZK test (see the design's
        // mask-translation argument and Merkle/ROM error bounds).
        let n = 32;
        let model = Model::new(n, vec![0; n * n]).unwrap();
        let config = matrix_config(n).unwrap();
        let h = config.num_variables / 2;
        let delta = Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5));
        let mut coins = PrivateRng::from_seed([91; 32]);
        let mut draw = || from_p3(coins.random::<E>());
        let keys: Vec<_> = (0..3 * h + 2).map(|_| Key::new(draw())).collect();
        let mut rows = keys.clone().into_iter();
        let input = vec![2; n];
        let output = vec![7; n]; // deliberately inconsistent with zero W
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let mut fs = matrix_statement(n, &model.root, &input, &output, attempt, &config).unwrap();
        let row_point: Vec<_> = (0..h).map(|_| fs.fp3()).collect();
        let public_sum =
            output.iter().zip(eq(&row_point)).fold(Fp3::ZERO, |s, (&y, r)| s + signed(y) * r);
        let mut target = Key::new(delta * public_sum);
        let mut public_input: Vec<_> = input.iter().map(|&x| signed(x as i64)).collect();
        let mut rounds = Vec::new();
        let mut point = row_point;
        for round in 0..h {
            fs.set_phase(1 + round as u16);
            let mut wire = [draw(), draw(), draw(), Fp3::ZERO];
            let next: [Key; 3] = std::array::from_fn(|i| {
                c7_fp3_transfer_verifier(
                    rows.next().unwrap(),
                    delta,
                    C7Fp3TransferCorrection::new(wire[i]),
                )
            });
            wire[3] = next[0].k + next[0].k + next[1].k + next[2].k - target.k;
            record_values(&mut fs, 0x10, &wire);
            let r = fs.fp3();
            target = next[0].add(next[1].scale(r)).add(next[2].scale(r * r));
            fold(&mut public_input, r);
            point.push(r);
            rounds.push(wire);
        }
        fs.set_phase(0x100);
        let correction = draw();
        let terminal_key = c7_fp3_transfer_verifier(
            rows.next().unwrap(),
            delta,
            C7Fp3TransferCorrection::new(correction),
        );
        let terminal = [correction, target.k - public_input[0] * terminal_key.k];
        record_values(&mut fs, 0x11, &terminal);
        let mask_key = rows.next().unwrap();
        assert!(rows.next().is_none());
        let point = Point::new(point.into_iter().map(to_p3).collect());
        let mut replay = fs.fork();
        let (pcs, _) = prove_pcs(
            &model,
            &config,
            point.clone(),
            Auth::ZERO,
            Auth::new(draw(), Fp3::ZERO),
            &mut fs,
        )
        .unwrap();
        // The simulator replaces the final tag using the received DV state.
        // There is no challenge after that tag, so the temporary dummy tag
        // inside prove_pcs is neither emitted nor used by any oracle request.
        replay.set_phase(0x200);
        replay.observe(model.root.clone());
        let mmcs = ObservedMmcs::new(replay.clone(), [0; 32]);
        let checked = HidingWhirVerifier::new(&config, &mmcs)
            .verify_claimless(&pcs, &model.root, &[point], &mut replay)
            .unwrap();
        let close_tag = mask_key.k
            + delta * from_p3(checked.base_case.combined - checked.base_case.shifted_masked_claim)
            - from_p3(checked.base_case.gamma)
                * (from_p3(checked.target.coefficient) * terminal_key.k
                    + delta * from_p3(checked.target.constant));
        record_values(&mut replay, 0x12, &[close_tag]);
        let proof = MatrixProof { rounds, terminal, pcs, close_tag };
        let verified = matrix_verify(
            n,
            &model.root,
            &input,
            &output,
            attempt,
            &proof,
            delta,
            &mut keys.into_iter(),
        )
        .unwrap();
        assert_eq!(verified, replay.digest());
    }

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
    fn c71_b12_private_coins_advance_discards_prefetch_preserves_stream_and_cap() {
        use rand_010::Rng;
        let seed = [19; 32];
        let mut hash = blake3::Hasher::new();
        hash.update(b"volta-zk/c71/b12/private-coins/v1\0"); hash.update(&seed);
        for end in [32u64, 63, 64, 4095, 4096, 4097, (1 << 40) - 17, 1 << 40] {
            let mut rng = PrivateRng::from_seed(seed);
            rng.fill_bytes(&mut [0; 32]);
            assert_eq!(rng.position(), 32);
            assert_eq!(rng.reader.position(), 4096);
            assert_eq!(rng.advance_to(end).unwrap(), end - 32);
            assert_eq!(rng.position(), end);
            assert!(rng.buffer.is_some());
            let mut reference = hash.finalize_xof(); reference.set_position(end);
            let count = 17.min(((1u64 << 40) - end) as usize);
            let mut actual = vec![0; count]; let mut expected = vec![0; count];
            rng.fill_bytes(&mut actual); reference.fill(&mut expected);
            assert_eq!(actual, expected);
            let position = rng.position();
            assert!(rng.advance_to(position - 1).is_err());
            assert!(rng.advance_to((1 << 40) + 1).is_err());
            assert_eq!(rng.position(), position);
            if position == 1 << 40 {
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rng.next_u64())).is_err());
            } else {
                let mut expected = [0; 8]; reference.fill(&mut expected);
                assert_eq!(rng.next_u64(), u64::from_le_bytes(expected));
            }
        }
    }

    #[test]
    fn c71_b12_private_coins_buffered_seek_snapshot_and_boundaries() {
        use rand_010::Rng;
        let seed = [19; 32];
        let mut rng = PrivateRng::from_seed(seed);
        let mut reference = rng.snapshot_at(0).unwrap();
        for size in [0, 4, 8, 1, 4080, 8, 4096, 7, 8193, 4095, 32] {
            let mut actual = vec![0; size];
            let mut expected = vec![0; size];
            rng.fill_bytes(&mut actual);
            reference.fill_bytes(&mut expected);
            assert_eq!(actual, expected);
            assert_eq!(rng.position(), reference.reader.position());
            // A snapshot continues at the logical cursor even inside a refill.
            let mut snapshot = rng.snapshot_at(rng.position()).unwrap();
            let mut expected = reference.snapshot_at(reference.position()).unwrap();
            assert_eq!(snapshot.next_u64(), expected.next_u64());
        }
        for offset in [0, 1, 7, 8, 63, 64, 4095, 4096, 4097, (1 << 40) - 17] {
            let mut replay = PrivateRng::replay_at(seed, offset).unwrap();
            let mut reference = rng.snapshot_at(offset).unwrap();
            let mut actual = [0; 17];
            let mut expected = [0; 17];
            replay.fill_bytes(&mut actual);
            reference.fill_bytes(&mut expected);
            assert_eq!(actual, expected);
            assert_eq!(replay.position(), offset + 17);
            assert!(replay.reader.position() <= 1 << 40);
            if offset == (1 << 40) - 17 {
                assert_eq!(replay.remaining, 0);
                replay.fill_bytes(&mut []);
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replay.next_u32())).is_err());
            }
        }
    }

    #[test]
    fn c71_b12_private_coins_device_xof_exact_live_seed_seek_salts_and_offsets() {
        use rand_010::{Rng, RngExt};
        use std::io::Write;
        use std::process::{Command, Stdio};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let directory = std::env::temp_dir().join(format!("c71-salts-{}-{}",
            std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let binary = directory.join("salts-host");
        let build = Command::new("g++").args(["-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I"])
            .arg(root.join("cuda")).arg(root.join("tests/c71_pcs_salts_host.cpp"))
            .arg("-o").arg(&binary).output().unwrap();
        assert!(build.status.success(), "{}", String::from_utf8_lossy(&build.stderr));
        let seeds = [[0; 32], [19; 32], std::array::from_fn(|i| i as u8), [0xa5; 32]];
        let offsets = [0, 1, 7, 8, 31, 32, 63, 64, 4095, 4096,
            (1u64 << 32) - 64, (1u64 << 38) - 64, 1u64 << 38, (1u64 << 40) - 128];
        let mut input = Vec::new();
        input.extend_from_slice(&((seeds.len() * offsets.len()) as u32).to_le_bytes());
        for seed in seeds {
            let mut hash = blake3::Hasher::new();
            hash.update(b"volta-zk/c71/b12/private-coins/v1\0"); hash.update(&seed);
            for offset in offsets {
                let mut reference = hash.finalize_xof(); reference.set_position(offset);
                let mut bytes = [0; 128]; reference.fill(&mut bytes);
                input.extend_from_slice(&seed); input.extend_from_slice(&offset.to_le_bytes());
                input.extend_from_slice(&128u32.to_le_bytes()); input.extend_from_slice(&bytes);
            }
        }
        let stream_count = 11u32;
        input.extend_from_slice(&stream_count.to_le_bytes());
        let mut append_stream = |rng: &mut PrivateRng, rows: u32, cosets: u32, cut: u32| {
            let origin = rng.position();
            input.extend_from_slice(&rng.seed); input.extend_from_slice(&origin.to_le_bytes());
            for x in [rows, cosets, cut] { input.extend_from_slice(&x.to_le_bytes()); }
            let mut positions = vec![origin];
            for _ in 0..u64::from(rows) * u64::from(cosets) {
                for _ in 0..4 {
                    let salt: Goldilocks = rng.random();
                    input.extend_from_slice(&salt.as_canonical_u64().to_le_bytes());
                }
                positions.push(rng.position());
            }
            for position in positions { input.extend_from_slice(&position.to_le_bytes()); }
        };
        for (i, origin) in [0, 1, 7, 32, 63, 64, 4095, (1u64 << 40) - 2048].into_iter().enumerate() {
            let mut rng = PrivateRng::replay_at([23 + i as u8; 32], origin).unwrap();
            let (rows, cosets, cut) = if i == 6 { (4096, 16, 4096) }
                else if i == 0 { (1, 4, 1) } else { (4, 16, 4) };
            append_stream(&mut rng, rows, cosets, cut);
        }
        // The canonical initial Tree clones MMCS before consuming salts.
        // Retain that exact live seed/cursor, including the sequential refill
        // that has moved the physical OutputReader beyond the logical cursor.
        let original_seed = [71; 32];
        let original = ObservedMmcs::new(Fs::new(b"device salts live MMCS parity", 0), original_seed);
        let extension = original.clone();
        original.inner.with_private_rng(|rng| {
            assert_eq!(rng.seed, original_seed); assert_eq!(rng.position(), 32);
            assert!(rng.reader.position() > rng.position());
            append_stream(rng, 8, 16, 16);
            append_stream(rng, 8, 16, 16); // consecutive commitment continuation
        });
        let mut expected_seed = [0; 32];
        PrivateRng::from_seed(original_seed).fill_bytes(&mut expected_seed);
        extension.inner.with_private_rng(|rng| {
            assert_eq!(rng.seed, expected_seed); assert_eq!(rng.position(), 0);
            append_stream(rng, 8, 16, 16);
        });
        let input_digest = blake3::hash(&input);
        let mut child = Command::new(&binary).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).unwrap();
        let report: serde_json::Value = serde_json::from_str(text.trim().strip_prefix("C71_PCS_SALTS_HOST ").unwrap()).unwrap();
        assert_eq!(report["vector_cases"], 56); assert_eq!(report["stream_cases"], stream_count);
        assert_eq!(report["byte_checks"], 56 * 128);
        assert_eq!(report["max_shape_scratch_bytes"], 10_520_320u64);
        assert_eq!(report["gpu_execution"], false); assert_eq!(report["credit"], false);
        println!("{}", text.trim());
        println!("C71_PCS_SALTS_REFERENCE {}", serde_json::json!({
            "stdin_bytes": input.len(), "stdin_blake3": input_digest.to_hex().to_string(),
            "rng_state_bytes": std::mem::size_of::<PrivateRng>(),
            "reference": "pinned Rust blake3 OutputReader and Goldilocks StandardUniform",
            "live_mmcs_cases": 3, "cuda_compilation": false, "gpu_execution": false, "credit": false}));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn c71_b12_private_coins_salts4_forced_rejection_and_exhaustion() {
        use rand_010::{Rng, RngExt};
        // Test-only tape in the sampler's existing buffer. The independent
        // oracle remains the pinned StandardUniform implementation.
        fn tape(words: &[u64], tail: u64) -> PrivateRng {
            let mut rng = PrivateRng::from_seed([29; 32]);
            let bytes = 8 * words.len();
            rng.remaining = bytes as u64 + tail;
            rng.reader.set_position((1 << 40) - tail);
            rng.cursor = 4096 - bytes;
            for (out, value) in rng.buffer.as_mut().unwrap()[rng.cursor..]
                .chunks_exact_mut(8).zip(words)
            {
                out.copy_from_slice(&value.to_le_bytes());
            }
            rng
        }
        for rejected in [Goldilocks::ORDER_U64, Goldilocks::ORDER_U64 + 1, u64::MAX] {
            for position in 0..4 {
                let mut words = vec![0, 1, 2, Goldilocks::ORDER_U64 - 1, 71];
                words.insert(position, rejected);
                let (mut actual, mut expected) = (tape(&words, 0), tape(&words, 0));
                let salts: [Goldilocks; 4] = std::array::from_fn(|_| expected.random());
                assert_eq!(actual.salts4(), salts);
                assert_eq!(actual.remaining, 8); // the fifth accepted word is untouched
                assert_eq!(actual.position(), expected.position());
                assert_eq!(actual.reader.position(), expected.reader.position());
                assert_eq!(actual.next_u64(), 71);
                assert_eq!(expected.next_u64(), 71);
            }
        }
        let words = [Goldilocks::ORDER_U64, 0, u64::MAX, 1,
            Goldilocks::ORDER_U64 + 1, 2, Goldilocks::ORDER_U64, 3];
        let (mut actual, mut expected) = (tape(&words, 0), tape(&words, 0));
        let salts: [Goldilocks; 4] = std::array::from_fn(|_| expected.random());
        assert_eq!(actual.salts4(), salts);
        assert_eq!(actual.position(), 1 << 40);
        assert_eq!(actual.position(), expected.position());
        // A shortened final batch consumes every available whole candidate,
        // including rejections, before failing on the next eight-byte read.
        for words in [&[][..], &[1][..], &[1, 2, 3][..], &words[..7]] {
            for tail in 0..8 {
                let (mut actual, mut expected) = (tape(words, tail), tape(words, tail));
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actual.salts4())).is_err());
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    std::array::from_fn::<Goldilocks, 4, _>(|_| expected.random())
                })).is_err());
                assert_eq!(actual.remaining, tail);
                assert_eq!(actual.position(), expected.position());
                assert_eq!(actual.reader.position(), expected.reader.position());
            }
        }
    }

    #[test]
    fn c71_b12_private_coins_salts4_seek_refill_and_stream_parity() {
        use rand_010::{Rng, RngExt};
        let original = PrivateRng::from_seed([41; 32]);
        for offset in [0, 1, 7, 8, 24, 40, 56, 63, 64, 4088, 4095, 4096, 4097, (1 << 40) - 32] {
            for buffered in [false, true] {
                let mut actual = if buffered { PrivateRng::replay_at([41; 32], offset).unwrap() }
                    else { original.snapshot_at(offset).unwrap() };
                let mut expected = original.snapshot_at(offset).unwrap();
                let groups = if offset == (1 << 40) - 32 { 1 } else { 160 };
                for _ in 0..groups {
                    let salts: [Goldilocks; 4] = std::array::from_fn(|_| expected.random());
                    assert_eq!(actual.salts4(), salts);
                    assert_eq!(actual.position(), expected.position());
                    assert!(actual.reader.position() <= 1 << 40);
                    if actual.remaining != 0 {
                        // Seeking from a partially prefetched buffer still
                        // resumes at the last consumed candidate byte.
                        let mut snapshot = actual.snapshot_at(actual.position()).unwrap();
                        let mut reference = expected.snapshot_at(expected.position()).unwrap();
                        assert_eq!(snapshot.next_u64(), reference.next_u64());
                    }
                }
                if actual.remaining == 0 {
                    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actual.salts4())).is_err());
                }
            }
        }
    }

    #[test]
    fn c71_b12_private_coins_salts4_component_benchmark() {
        use rand_010::RngExt;
        use std::{hint::black_box, time::Instant};
        let original = PrivateRng::from_seed([73; 32]);
        let leaves = 65_536usize;
        let (rows, cosets, repetitions) = (2048usize, 4096usize, 3usize);
        let offset = |i: usize| 32 * ((i % rows) * cosets + i / rows) as u64;
        let mut candidate_bytes = 0;
        for i in 0..leaves {
            let mut actual = original.snapshot_at(offset(i)).unwrap();
            let mut expected = original.snapshot_at(offset(i)).unwrap();
            let salts: [Goldilocks; 4] = std::array::from_fn(|_| expected.random());
            assert_eq!(actual.salts4(), salts);
            assert_eq!(actual.position(), expected.position());
            candidate_bytes += actual.position() - offset(i);
        }
        let mut schedules = Vec::new();
        for strided in [false, true] {
            let mut seconds = [Vec::new(), Vec::new()];
            for repetition in 0..repetitions {
                // Alternate the order; every mode uses this same binary,
                // source stream and number of accepted salts.
                for batched in [repetition % 2 == 0, repetition % 2 != 0] {
                    let mut sequential = PrivateRng::from_seed([73; 32]);
                    let start = Instant::now();
                    for i in 0..leaves {
                        let mut snapshot;
                        let rng = if strided {
                            snapshot = original.snapshot_at(offset(i)).unwrap();
                            &mut snapshot
                        } else { &mut sequential };
                        let salts: [Goldilocks; 4] = if batched { rng.salts4() }
                            else { std::array::from_fn(|_| rng.random()) };
                        let _ = black_box(salts);
                    }
                    seconds[usize::from(batched)].push(start.elapsed().as_secs_f64());
                }
            }
            schedules.push(serde_json::json!({"strided": strided,
                "ordinary_seconds": seconds[0], "salts4_seconds": seconds[1]}));
        }
        println!("C71_XOF_SALTS4_COMPONENT {}", serde_json::json!({
            "credit": false, "gpu_execution": false, "same_binary": true,
            "leaf_pairs_checked": leaves, "accepted_salts_per_mode": 4 * leaves,
            "parity_candidate_bytes": candidate_bytes, "repetitions": repetitions,
            "strided_rows": rows, "strided_cosets": cosets, "stack_batch_bytes": 32,
            "schedules": schedules,
            "scope": "local sequential and strided sampler; not H100 or whole PCS"
        }));
    }

    #[test]
    fn c71_b12_private_coins_buffered_component_benchmark() {
        use rand_010::{Rng, RngExt};
        use std::{hint::black_box, time::Instant};
        let samples = 262_144;
        let mut seconds = Vec::new();
        for buffered in [false, true] {
            let mut rng = PrivateRng::from_seed([73; 32]);
            if !buffered { rng = rng.snapshot_at(0).unwrap(); }
            let mut expected = rng.snapshot_at(0).unwrap();
            for _ in 0..samples {
                assert_eq!(rng.random::<Goldilocks>(), expected.random::<Goldilocks>());
            }
            assert_eq!(rng.position(), expected.position());
            let started = Instant::now();
            for _ in 0..samples { let _ = black_box(rng.random::<Goldilocks>()); }
            seconds.push(started.elapsed().as_secs_f64());
            black_box(rng.next_u64());
        }
        println!("C71_XOF_COMPONENT {}", serde_json::json!({
            "credit": false, "samples_per_mode": samples, "buffer_bytes": 4096,
            "unbuffered_seconds": seconds[0], "buffered_seconds": seconds[1],
            "speedup": seconds[0] / seconds[1],
            "scope": "local sequential Goldilocks sampler; not H100 or whole PCS"
        }));
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

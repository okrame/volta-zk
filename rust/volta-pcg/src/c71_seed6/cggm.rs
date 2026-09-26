//! Test-only role-separated guard-to-cGGM bridge and original-row split checks.
//! The caller owns global coins, transport, nonce freshness and one-use burn.
use super::{Error, GuardAccepted, ProverFinished};
use crate::c71_bootstrap::{random_bytes, sample_fp};
use crate::c71_ea_lpn::{add_work, cggm_h, Work};
use crate::c71_seed6::Fp3Words;
use rand::{CryptoRng, RngCore};
use volta_field::{Fp, Fp3};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"VOLTA-C71-Seed6-cggm-corrections-v1";

#[path = "expand.rs"]
mod expand;

struct SenderPending {
    guard: GuardAccepted,
    nonce: [u8; 32],
    roots: Zeroizing<Vec<[Fp3Words; 2]>>,
    prefix: [u8; 32],
    work: Work,
    random_candidates: u64,
}

struct ReceiverPending {
    guard: ProverFinished,
    nonce: [u8; 32],
    alpha: Zeroizing<Vec<u64>>,
    keys: Zeroizing<Vec<Fp3Words>>,
    prefix: [u8; 32],
    work: Work,
}

struct SplitPending<State> {
    state: State,
    values: Zeroizing<Vec<Fp3Words>>,
    work: Work,
}

fn canonical_words(wire: &[u8], count: usize) -> Result<(), Error> {
    if wire.len() != 24 * count {
        return Err(Error::Shape);
    }
    if wire
        .chunks_exact(8)
        .any(|limb| u64::from_le_bytes(limb.try_into().unwrap()) >= volta_field::P)
    {
        return Err(Error::Noncanonical);
    }
    Ok(())
}

fn prefix(guard: [u8; 32], nonce: [u8; 32], wire: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(DOMAIN);
    hash.update(&guard);
    hash.update(&nonce);
    hash.update(&(wire.len() as u64).to_le_bytes());
    hash.update(wire);
    *hash.finalize().as_bytes()
}

fn walk(
    nonce: [u8; 32],
    block: usize,
    height: usize,
    depth: usize,
    position: u64,
    node: Fp3,
    visit: &mut impl FnMut(usize, u64, Fp3) -> Result<(), Error>,
    work: &mut Work,
) -> Result<(), Error> {
    work.recursive_frames_peak = work.recursive_frames_peak.max(height - depth + 1);
    visit(depth, position, node)?;
    if depth < height {
        let (left, hash_work) = cggm_h(nonce, block as u64, depth as u32, position, node)
            .map_err(|_| Error::Rejected)?;
        add_work(work, hash_work);
        let right = node - left;
        work.fp3_subtractions += 1;
        walk(nonce, block, height, depth + 1, 2 * position, left, visit, work)?;
        walk(nonce, block, height, depth + 1, 2 * position + 1, right, visit, work)?;
    }
    Ok(())
}

impl GuardAccepted {
    fn cggm(
        self,
        nonce: [u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, SenderPending), Error> {
        let (blocks, height) = (self.frozen.blocks, self.frozen.height);
        if nonce == [0; 32] || self.seed.keys.len() != self.frozen.mask_start() + 3 {
            return Err(Error::Shape);
        }
        let mut roots = Zeroizing::new(Vec::with_capacity(blocks));
        let mut wire = Vec::with_capacity(24 * blocks * height);
        let mut work = Work::default();
        let mut sampling = crate::c71_bootstrap::Work::default();
        for block in 0..blocks {
            let row = block * (height + 4);
            let delta = self.seed.delta.fp3();
            let corrections = &self.frozen.corrections[block * (height + 1)..][..height + 1];
            let offset = self.seed.keys[row].fp3() - delta.mul_base(Fp::new(corrections[0]));
            let key = |level: usize| {
                -self.seed.keys[row + 1 + level].fp3()
                    - delta.mul_base(Fp::new(corrections[1 + level]))
            };
            let mut random = Zeroizing::new([0u64; 3]);
            for limb in random.iter_mut() {
                *limb = sample_fp(|bytes| random_bytes(rng, bytes), &mut sampling)
                    .map_err(|_| Error::Rejected)?;
            }
            let first_left =
                Fp3::new(Fp::new(random[0]), Fp::new(random[1]), Fp::new(random[2])) - key(0);
            let children = [first_left, offset - first_left];
            let mut sums = Zeroizing::new(vec![Fp3Words::default(); height]);
            let mut additions = 0;
            for (position, node) in children.into_iter().enumerate() {
                walk(
                    nonce,
                    block,
                    height,
                    1,
                    position as u64,
                    node,
                    &mut |depth, position, value| {
                        if position & 1 == 0 {
                            sums[depth - 1] = Fp3Words::from_fp3(sums[depth - 1].fp3() + value);
                            additions += 1;
                        }
                        Ok(())
                    },
                    &mut work,
                )?;
            }
            for (level, sum) in sums.iter().enumerate() {
                wire.extend_from_slice(&(key(level) + sum.fp3()).to_bytes());
            }
            roots.push(children.map(Fp3Words::from_fp3));
            work.fp3_by_fp_multiplications += height as u64 + 2;
            work.fp3_subtractions += 2 * height as u64 + 5;
            work.fp3_additions += additions + height as u64;
        }
        let prefix = prefix(self.frozen.prefix, nonce, &wire);
        Ok((
            wire,
            SenderPending {
                guard: self,
                nonce,
                roots,
                prefix,
                work,
                random_candidates: sampling.field_candidates,
            },
        ))
    }
}

impl ProverFinished {
    fn cggm(self, nonce: [u8; 32], paths: Vec<u64>, wire: &[u8]) -> Result<ReceiverPending, Error> {
        let (blocks, height) = (self.frozen.blocks, self.frozen.height);
        let mut alpha = Zeroizing::new(paths);
        if nonce == [0; 32]
            || self.seed.values.len() != self.frozen.mask_start() + 3
            || alpha.len() != blocks
            || alpha.capacity() != blocks
            || alpha.iter().any(|&path| path >= 1 << height)
        {
            return Err(Error::Shape);
        }
        canonical_words(wire, blocks * height)?;
        let mut keys = Zeroizing::new(Vec::with_capacity(blocks * (height + 1)));
        let mut work = Work::default();
        for block in 0..blocks {
            let row = block * (height + 4);
            let corrections = &self.frozen.corrections[block * (height + 1)..][..height + 1];
            let beta = Fp::new(self.seed.values[row]) + Fp::new(corrections[0]);
            let tag = self.seed.tags[row].fp3();
            let mut known = Zeroizing::new(vec![[Fp3Words::default(); 2]; height]);
            let mut sum_siblings = Fp3::ZERO;
            for level in 0..height {
                let bit = (alpha[block] >> (height - 1 - level)) & 1;
                if Fp::new(self.seed.values[row + 1 + level]) - Fp::new(corrections[1 + level])
                    != beta * Fp::new(bit)
                {
                    return Err(Error::Rejected);
                }
                let start = 24 * (block * height + level);
                let correction =
                    Fp3::from_bytes(&wire[start..start + 24]).map_err(|_| Error::Noncanonical)?;
                let masked = tag.mul_base(Fp::new(bit)) - self.seed.tags[row + 1 + level].fp3();
                let left_sum = correction - masked;
                let sibling = (if bit == 0 { left_sum } else { -left_sum })
                    - known[level][bit as usize].fp3();
                keys.push(Fp3Words::from_fp3(sibling));
                sum_siblings += sibling;
                let position = ((alpha[block] ^ ((1 << height) - 1)) >> (height - level - 1)) ^ 1;
                let mut additions = 0;
                walk(
                    nonce,
                    block,
                    height,
                    level + 1,
                    position,
                    sibling,
                    &mut |depth, position, value| {
                        let target = &mut known[depth - 1][(position & 1) as usize];
                        *target = Fp3Words::from_fp3(target.fp3() + value);
                        additions += 1;
                        Ok(())
                    },
                    &mut work,
                )?;
                work.fp3_additions += additions + 1;
                work.fp3_subtractions += 3 + bit;
                work.fp3_by_fp_multiplications += 1;
            }
            keys.push(Fp3Words::from_fp3(tag - sum_siblings));
            work.fp3_subtractions += 1;
            alpha[block] ^= (1 << height) - 1;
        }
        let prefix = prefix(self.frozen.prefix, nonce, wire);
        Ok(ReceiverPending { guard: self, nonce, alpha, keys, prefix, work })
    }
}

impl SenderPending {
    fn split(
        self,
        wire: &[u8],
        mut coefficient: impl FnMut([u8; 32], usize, u64) -> Result<Fp3, Error>,
    ) -> Result<SplitPending<Self>, Error> {
        let (blocks, height) = (self.guard.frozen.blocks, self.guard.frozen.height);
        canonical_words(wire, blocks)?;
        let mut values = Zeroizing::new(Vec::with_capacity(blocks));
        let mut work = Work::default();
        for block in 0..blocks {
            let mut value = Fp3::ZERO;
            for (position, node) in self.roots[block].iter().enumerate() {
                walk(
                    self.nonce,
                    block,
                    height,
                    1,
                    position as u64,
                    node.fp3(),
                    &mut |depth, leaf, node| {
                        if depth == height {
                            value += coefficient(self.prefix, block, leaf)? * node;
                        }
                        Ok(())
                    },
                    &mut work,
                )?;
            }
            let correction = Fp3::from_bytes(&wire[24 * block..24 * (block + 1)])
                .map_err(|_| Error::Noncanonical)?;
            let mask = super::pack_key(&self.guard.seed, block * (height + 4) + height + 1);
            values.push(Fp3Words::from_fp3(
                value + mask.k + self.guard.seed.delta.fp3() * correction,
            ));
            work.fp3_multiplications += (1 << height) + 4;
            work.fp3_additions += (1 << height) + 5;
        }
        Ok(SplitPending { state: self, values, work })
    }
}

impl ReceiverPending {
    fn split(
        self,
        mut coefficient: impl FnMut([u8; 32], usize, u64) -> Result<Fp3, Error>,
    ) -> Result<(Vec<u8>, SplitPending<Self>), Error> {
        let (blocks, height) = (self.guard.frozen.blocks, self.guard.frozen.height);
        let mut wire = Vec::with_capacity(24 * blocks);
        let mut values = Zeroizing::new(Vec::with_capacity(blocks));
        let mut work = Work::default();
        for block in 0..blocks {
            let mut value = Fp3::ZERO;
            let words = &self.keys[block * (height + 1)..][..height + 1];
            let left_siblings =
                (0..height).filter(|&level| self.alpha[block] >> (height - level - 1) & 1 == 1);
            let right_siblings = (0..height)
                .rev()
                .filter(|&level| self.alpha[block] >> (height - level - 1) & 1 == 0);
            let mut alpha_coefficient = None;
            for level in left_siblings.chain(right_siblings) {
                let position = (self.alpha[block] >> (height - level - 1)) ^ 1;
                if alpha_coefficient.is_none()
                    && self.alpha[block] < position << (height - level - 1)
                {
                    let alpha = coefficient(self.prefix, block, self.alpha[block])?;
                    value += alpha * words[height].fp3();
                    alpha_coefficient = Some(alpha);
                }
                walk(
                    self.nonce,
                    block,
                    height,
                    level + 1,
                    position,
                    words[level].fp3(),
                    &mut |depth, leaf, node| {
                        if depth == height {
                            value += coefficient(self.prefix, block, leaf)? * node;
                        }
                        Ok(())
                    },
                    &mut work,
                )?;
            }
            let alpha_coefficient = match alpha_coefficient {
                Some(alpha) => alpha,
                None => {
                    let alpha = coefficient(self.prefix, block, self.alpha[block])?;
                    value += alpha * words[height].fp3();
                    alpha
                }
            };
            let row = block * (height + 4);
            let beta = Fp::new(self.guard.seed.values[row])
                + Fp::new(self.guard.frozen.corrections[block * (height + 1)]);
            let mask = super::pack_auth(&self.guard.seed, row + height + 1);
            wire.extend_from_slice(&(mask.x + alpha_coefficient.mul_base(beta)).to_bytes());
            values.push(Fp3Words::from_fp3(value + mask.m));
            work.fp3_multiplications += (1 << height) + 6;
            work.fp3_additions += (1 << height) + 8;
            work.fp3_by_fp_multiplications += 1;
        }
        Ok((wire, SplitPending { state: self, values, work }))
    }
}

pub(super) fn check_real(prover: ProverFinished, verifier: GuardAccepted) {
    let nonce = verifier.seed.binding;
    let (wire, sender) = verifier.cggm(nonce, &mut rand::thread_rng()).unwrap();
    let receiver = prover.cggm(nonce, vec![2], &wire).unwrap();
    tests::check(&sender, &receiver, &[17]);
    eprintln!("C71_GUARD_CGGM_REAL rows=9 original_macs=true split_and_equality_pending=true");
}

#[cfg(test)]
mod tests {
    use super::super::{corrections, ProverGuard, VerifierGuard};
    use super::*;
    use crate::c71_ea_lpn::{acc, punc_acc, PuncturedKey};
    use crate::c71_seed6::coins::{self, tests::BadRng};
    use rand::{rngs::StdRng, SeedableRng};

    fn guarded(height: usize, betas: &[u64], paths: &[u64]) -> (ProverFinished, GuardAccepted) {
        let (mut prover, mut verifier) = super::super::tests::fixture();
        let rows = betas.len() * (height + 4) + 3;
        assert!(rows <= prover.values.len());
        prover.values.truncate(rows);
        prover.tags.truncate(rows);
        verifier.keys.truncate(rows);
        guarded_outputs(prover, verifier, height, betas, paths)
    }

    fn guarded_outputs(
        prover: super::super::RealProverOutput,
        verifier: super::super::RealVerifierOutput,
        height: usize,
        betas: &[u64],
        paths: &[u64],
    ) -> (ProverFinished, GuardAccepted) {
        let correction = corrections(&prover, height, betas, paths).unwrap();
        let prover = ProverGuard::freeze(prover, betas.len(), height, correction.clone()).unwrap();
        let verifier = VerifierGuard::freeze(verifier, betas.len(), height, correction).unwrap();
        assert_eq!(prover.frozen.prefix, verifier.frozen.prefix);
        let verifier = verifier.challenge_bound().unwrap();
        let (wire, finished) = prover.prove_bound().unwrap();
        (finished, verifier.verify(&wire).unwrap())
    }

    fn coefficient(prefix: [u8; 32], block: usize, leaf: u64) -> Result<Fp3, Error> {
        assert_ne!(prefix, [0; 32]);
        Ok(Fp3::new(Fp::new(leaf + 1), Fp::new(block as u64 + 2), Fp::new((leaf + 1).pow(2))))
    }

    fn check_split(sender: SenderPending, receiver: ReceiverPending) {
        let sender_hashes = sender.work.shake_calls;
        let receiver_hashes = receiver.work.shake_calls;
        let (blocks, height) = (sender.guard.frozen.blocks, sender.guard.frozen.height);
        let mut next = 0;
        let (wire, receiver) = receiver
            .split(|prefix, block, leaf| {
                assert_eq!(((block as u64) << height) + leaf, next);
                next += 1;
                coefficient(prefix, block, leaf)
            })
            .unwrap();
        next = 0;
        let sender = sender
            .split(&wire, |prefix, block, leaf| {
                assert_eq!(((block as u64) << height) + leaf, next);
                next += 1;
                coefficient(prefix, block, leaf)
            })
            .unwrap();
        assert_eq!(sender.values, receiver.values);
        assert_eq!(sender.state.prefix, receiver.state.prefix);
        assert_eq!(wire.len(), 24 * blocks);
        assert_eq!(sender.work.shake_calls, sender_hashes);
        assert_eq!(receiver.work.shake_calls, receiver_hashes);
        assert_eq!(sender.work.fp3_multiplications, blocks as u64 * ((1 << height) + 4));
        assert_eq!(receiver.work.fp3_multiplications, blocks as u64 * ((1 << height) + 6));
        assert_eq!(sender.work.fp3_additions, blocks as u64 * ((1 << height) + 5));
        assert_eq!(receiver.work.fp3_additions, blocks as u64 * ((1 << height) + 8));
        assert_eq!(sender.values.capacity(), blocks);
        assert_eq!(receiver.values.capacity(), blocks);
    }

    pub(super) fn check(sender: &SenderPending, receiver: &ReceiverPending, betas: &[u64]) {
        super::super::check_remaining(&receiver.guard, &sender.guard);
        assert_eq!(sender.prefix, receiver.prefix);
        assert_eq!(sender.nonce, receiver.nonce);
        let height = sender.guard.frozen.height;
        let blocks = betas.len() as u64;
        let leaves = 1u64 << height;
        assert_eq!(sender.roots.len(), betas.len());
        assert_eq!(receiver.keys.len(), betas.len() * (height + 1));
        assert_eq!(sender.random_candidates, 24 * betas.len() as u64);
        assert_eq!(sender.work.shake_calls, betas.len() as u64 * ((1 << height) - 2));
        assert_eq!(
            receiver.work.shake_calls,
            betas.len() as u64 * ((1 << height) - height as u64 - 1)
        );
        assert!(sender.work.recursive_frames_peak <= height);
        assert!(receiver.work.recursive_frames_peak <= height);
        assert_eq!(sender.roots.capacity(), betas.len());
        assert_eq!(receiver.keys.capacity(), betas.len() * (height + 1));
        assert_eq!(receiver.alpha.capacity(), betas.len());
        assert_eq!(sender.work.fp3_additions, blocks * (leaves - 1 + height as u64));
        assert_eq!(receiver.work.fp3_additions, blocks * (2 * leaves - 2));
        assert_eq!(sender.work.fp3_subtractions, blocks * (leaves + 2 * height as u64 + 3));
        let ones: u64 =
            receiver.alpha.iter().map(|alpha| ((leaves - 1) ^ alpha).count_ones() as u64).sum();
        assert_eq!(receiver.work.fp3_subtractions, blocks * (leaves + 2 * height as u64) + ones);
        assert_eq!(sender.work.fp3_by_fp_multiplications, blocks * (height as u64 + 2));
        assert_eq!(receiver.work.fp3_by_fp_multiplications, blocks * height as u64);
        for (block, &beta) in betas.iter().enumerate() {
            let children = sender.roots[block].map(Fp3Words::fp3);
            let words = &receiver.keys[block * (height + 1)..][..height + 1];
            let key = PuncturedKey {
                alpha: receiver.alpha[block],
                height,
                siblings: words[..height].iter().map(|value| value.fp3()).collect(),
                alternative_leaf: words[height].fp3(),
            };
            for omega in 0..1 << height {
                let value = acc(
                    sender.nonce,
                    block as u64,
                    height,
                    omega,
                    children[0] + children[1],
                    children[0],
                )
                .unwrap()
                .0;
                let tag = punc_acc(receiver.nonce, block as u64, omega, &key).unwrap().0;
                let expected = if omega >= key.alpha {
                    sender.guard.seed.delta.fp3().mul_base(Fp::new(beta))
                } else {
                    Fp3::ZERO
                };
                assert_eq!(tag - value, expected, "block={block} omega={omega}");
            }
        }
    }

    #[test]
    fn c71_seed6_guard_cggm_separate_roles_all_small_paths() {
        let mut rng = StdRng::seed_from_u64(1001);
        for height in 1..=7 {
            for path in 0..1 << height {
                let beta = if path % 3 == 0 { 0 } else { 17 };
                let (prover, verifier) = guarded(height, &[beta], &[path]);
                let (wire, sender) = verifier.cggm([7; 32], &mut rng).unwrap();
                assert_eq!(wire.len(), 24 * height);
                let receiver = prover.cggm([7; 32], vec![path], &wire).unwrap();
                assert_eq!(receiver.alpha[0], path ^ ((1 << height) - 1));
                check(&sender, &receiver, &[beta]);
                check_split(sender, receiver);
            }
        }
        for first in 0..4 {
            for second in 0..4 {
                let (prover, verifier) = guarded(2, &[17, 0], &[first, second]);
                let (wire, sender) = verifier.cggm([7; 32], &mut rng).unwrap();
                let receiver = prover.cggm([7; 32], vec![first, second], &wire).unwrap();
                check(&sender, &receiver, &[17, 0]);
                check_split(sender, receiver);
            }
        }
        eprintln!(
            "C71_GUARD_CGGM heights=1..7 roles_separate=true beta_zero=true split_checks=true full_bootstrap=false"
        );
        eprintln!(
            "seed6_cggm_native_sizes {}",
            serde_json::json!({
                "sender_pending":size_of::<SenderPending>(),
                "receiver_pending":size_of::<ReceiverPending>(),
                "sender_split_pending":size_of::<SplitPending<SenderPending>>(),
                "receiver_split_pending":size_of::<SplitPending<ReceiverPending>>(),
                "complete_physical_peak":false
            })
        );
    }

    #[test]
    fn c71_seed6_guard_cggm_rejects_shapes_codec_and_changed_private_path() {
        for fault in 0..7 {
            let (prover, verifier) = guarded(2, &[17, 0], &[2, 1]);
            let (mut wire, _) = verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1002)).unwrap();
            let (mut nonce, mut paths) = ([7; 32], vec![2, 1]);
            match fault {
                0 => {
                    wire.pop();
                }
                1 => wire[..8].copy_from_slice(&volta_field::P.to_le_bytes()),
                2 => paths[0] = 1,
                3 => paths[0] = 4,
                4 => {
                    paths.pop();
                }
                5 => nonce = [0; 32],
                _ => paths.reserve(1),
            }
            assert!(prover.cggm(nonce, paths, &wire).is_err());
        }
        let (_, verifier) = guarded(2, &[17], &[2]);
        assert!(verifier.cggm([0; 32], &mut StdRng::seed_from_u64(1003)).is_err());
        let (prover, verifier) = super::super::tests::fixture();
        let (prover, verifier) = guarded_outputs(prover, verifier, 2, &[17], &[2]);
        assert!(verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1003)).is_err());
        assert!(prover.cggm([7; 32], vec![2], &[0; 48]).is_err());
        let (prover, verifier) = guarded(2, &[17], &[2]);
        let (mut wire, sender) = verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1004)).unwrap();
        wire[0] ^= 1;
        let receiver = prover.cggm([7; 32], vec![2], &wire).unwrap();
        assert_ne!(receiver.prefix, sender.prefix);
        let (wire, receiver) = receiver.split(coefficient).unwrap();
        let sender = sender.split(&wire, coefficient).unwrap();
        assert_ne!(sender.values, receiver.values);
        for fault in 0..2 {
            let (prover, verifier) = guarded(2, &[17], &[2]);
            let (wire, sender) = verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1005)).unwrap();
            let receiver = prover.cggm([7; 32], vec![2], &wire).unwrap();
            let (mut wire, _) = receiver.split(coefficient).unwrap();
            if fault == 0 {
                wire.pop();
            } else {
                wire[..8].copy_from_slice(&volta_field::P.to_le_bytes());
            }
            assert!(sender.split(&wire, coefficient).is_err());
        }
    }

    #[test]
    fn c71_seed6_guard_cggm_randomness_and_sampler_fail_closed() {
        for unavailable in [false, true] {
            let (_, verifier) = guarded(2, &[17], &[2]);
            assert!(matches!(
                verifier.cggm([7; 32], &mut BadRng(unavailable)),
                Err(Error::Rejected)
            ));
        }
        let (prover, verifier) = guarded(2, &[17], &[2]);
        let (wire, sender) = verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1010)).unwrap();
        let receiver = prover.cggm([7; 32], vec![2], &wire).unwrap();
        assert!(matches!(receiver.split(|_, _, _| Err(Error::Rejected)), Err(Error::Rejected)));
        assert!(matches!(
            sender.split(&[0; 24], |_, _, _| Err(Error::Rejected)),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn c71_seed6_real_guard_cggm_split_and_two_key_equality() {
        use crate::c71_seed6::{equality::tests as equality, real};
        for fault in 0..3 {
            let (main_prover, main_verifier) = equality::real_pair(25, 0);
            let (opposite_prover, opposite_verifier) = equality::real_pair(6, 1);
            let main_prover = real::reserve_equality_prover_tail(main_prover, 6).unwrap();
            let main_verifier = real::reserve_equality_verifier_tail(main_verifier, 6).unwrap();
            let (prover, verifier) =
                guarded_outputs(main_prover.prefix, main_verifier.prefix, 4, &[17, 23], &[13, 5]);
            let context =
                coins::Context::new([7; 32], prover.frozen.prefix, coins::Phase::Split, 32)
                    .unwrap();
            let (commitment, committed) =
                coins::Committed::new(context, &mut StdRng::seed_from_u64(1007)).unwrap();
            let (mut wire, mut sender) =
                verifier.cggm([7; 32], &mut StdRng::seed_from_u64(1006)).unwrap();
            let (response, replied) =
                coins::Replied::new(context, &commitment, &mut StdRng::seed_from_u64(1008))
                    .unwrap();
            if fault == 1 {
                wire[0] ^= 1;
                sender.prefix = prefix(sender.guard.frozen.prefix, sender.nonce, &wire);
            }
            let receiver = prover.cggm([7; 32], vec![13, 5], &wire).unwrap();
            assert_eq!(sender.prefix, receiver.prefix);
            let (opening, mut receiver_coins) = committed.open(&response, receiver.prefix).unwrap();
            let mut sender_coins = replied.open(&opening, sender.prefix).unwrap();
            let (mut wire, receiver) = receiver
                .split(|prefix, block, leaf| {
                    receiver_coins
                        .draw(prefix, 16 * block as u64 + leaf)
                        .map_err(|_| Error::Rejected)
                })
                .unwrap();
            if fault == 2 {
                wire[0] ^= 1;
            }
            let sender = sender
                .split(&wire, |prefix, block, leaf| {
                    sender_coins.draw(prefix, 16 * block as u64 + leaf).map_err(|_| Error::Rejected)
                })
                .unwrap();
            assert_eq!(sender_coins.finish().unwrap().squeezed_bytes, 32 * 192);
            assert_eq!(receiver_coins.finish().unwrap().squeezed_bytes, 32 * 192);
            let (accepted_sender, accepted_receiver) = equality::finish_chosen_inputs(
                opposite_prover,
                main_verifier.equality_tail,
                main_prover.equality_tail,
                opposite_verifier,
                sender.values,
                receiver.values,
                sender.state,
                receiver.state,
            );
            assert_eq!(accepted_sender.is_ok(), fault == 0);
            assert_eq!(accepted_receiver.is_ok(), fault == 0);
            if fault == 0 {
                let mut sender =
                    expand::Sender::new(accepted_sender.unwrap(), [0x61; 32], 2).unwrap();
                let mut receiver =
                    expand::Receiver::new(accepted_receiver.unwrap(), [0x61; 32], 2).unwrap();
                assert_eq!(sender.binding, receiver.binding);
                assert_eq!(sender.heap_bytes(), 96);
                assert_eq!(receiver.heap_bytes(), 320);
                let delta = sender.delta();
                let (mut packed_value, mut packed_tag, mut packed_key) =
                    (Fp3::ZERO, Fp3::ZERO, Fp3::ZERO);
                for row_index in 0..6 {
                    let basis = super::super::BASIS[row_index as usize % 3];
                    let key = sender.next_row().unwrap();
                    let row = receiver.next_row().unwrap();
                    let (terms, _) =
                        crate::c71_ea_lpn::public_ea_row([0x61; 32], row_index, 32, 2).unwrap();
                    let expected = terms.iter().fold(Fp::ZERO, |sum, term| {
                        let prefix =
                            [(2, 17), (26, 23)].iter().fold(Fp::ZERO, |sum, &(position, beta)| {
                                if term.index >= position {
                                    sum + Fp::new(beta)
                                } else {
                                    sum
                                }
                            });
                        sum + term.coefficient * prefix
                    });
                    assert_eq!(
                        Fp::new(row[0]),
                        expected,
                        "global EA accumulator at row {row_index}"
                    );
                    let key = Fp3::new(Fp::new(key[0]), Fp::new(key[1]), Fp::new(key[2]));
                    let tag = Fp3::new(Fp::new(row[1]), Fp::new(row[2]), Fp::new(row[3]));
                    assert_eq!(tag, key + delta.mul_base(Fp::new(row[0])));
                    packed_value += basis.mul_base(Fp::new(row[0]));
                    packed_tag += basis * tag;
                    packed_key += basis * key;
                    if row_index % 3 == 2 {
                        assert_ne!(packed_value, Fp3::ZERO);
                        assert_eq!(packed_tag, packed_key + delta * packed_value);
                        (packed_value, packed_tag, packed_key) = (Fp3::ZERO, Fp3::ZERO, Fp3::ZERO);
                    }
                }
                assert_eq!(receiver.base_mul_add_pairs, 12);
                assert_eq!(sender.work.fp3_by_fp_multiplications, 12);
                assert_eq!(receiver.work.fp3_by_fp_multiplications, 12);
                assert_eq!(sender.work.shake_calls, 60);
                assert!(receiver.work.shake_calls <= 60);
                for _ in 0..2 {
                    assert!(sender.next_row().is_err());
                    assert!(receiver.next_row().is_err());
                }
                assert_eq!(sender.delta(), Fp3::ZERO);
            }
        }
        eprintln!("C71_SEED6_CGGM_EQUALITY main_rows=25 inverse_rows=6 original_macs=true altered_c_and_z_rejected=true both_coin_commit_open=true EA_rows_after_acceptance=6 global_EA_accumulator=true durable_burn=false");
    }
}

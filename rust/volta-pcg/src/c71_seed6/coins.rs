//! Test-only commit/response/open coins for split and equality checks.
//! The outer caller must freeze all c before opening, seal both seeds, and
//! durably burn the setup on any error. This is not a lifetime or transport.
use crate::c71_bootstrap::random_bytes;
use crate::c71_ea_lpn::{sample_h_limbs, Work};
use rand::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256Reader};
use volta_field::Fp3;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"VOLTA-C71-DORY-COIN-v1";
type Result<Value> = std::result::Result<Value, &'static str>;

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Split,
    Equality,
}

#[derive(Clone, Copy)]
pub(super) struct Context {
    nonce: [u8; 32],
    prefix: [u8; 32],
    phase: Phase,
    count: u64,
}

impl Context {
    pub(super) fn new(nonce: [u8; 32], prefix: [u8; 32], phase: Phase, count: u64) -> Result<Self> {
        let cap = match phase {
            Phase::Split => 675 << 19,
            Phase::Equality => 675,
        };
        if nonce == [0; 32] || prefix == [0; 32] || count == 0 || count > cap {
            return Err("coin context");
        }
        Ok(Self { nonce, prefix, phase, count })
    }

    fn commitment(self, opening: &[u8; 64]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(DOMAIN);
        hash.update(&self.nonce);
        hash.update(&self.prefix);
        hash.update(&[self.phase as u8, 1]);
        hash.update(&self.count.to_le_bytes());
        hash.update(opening);
        *hash.finalize().as_bytes()
    }
}

pub(super) struct Committed {
    context: Context,
    opening: Zeroizing<[u8; 64]>,
}

pub(super) struct Replied {
    context: Context,
    commitment: [u8; 32],
    seed: Zeroizing<[u8; 32]>,
}

impl Committed {
    pub(super) fn new(
        context: Context,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<([u8; 32], Self)> {
        let mut opening = Zeroizing::new([0; 64]);
        random_bytes(rng, &mut opening[..]).map_err(|_| "coin randomness")?;
        Ok((context.commitment(&opening), Self { context, opening }))
    }

    pub(super) fn open(
        self,
        response: &[u8],
        frozen_prefix: [u8; 32],
    ) -> Result<([u8; 64], Coefficients)> {
        let response: &[u8; 32] = response.try_into().map_err(|_| "coin response length")?;
        let seed = std::array::from_fn(|index| response[index] ^ self.opening[index]);
        let coefficients = Coefficients::new(self.context, frozen_prefix, seed)?;
        Ok((*self.opening, coefficients))
    }
}

impl Replied {
    pub(super) fn new(
        context: Context,
        commitment: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<([u8; 32], Self)> {
        let commitment = commitment.try_into().map_err(|_| "coin commitment length")?;
        let mut seed = Zeroizing::new([0; 32]);
        random_bytes(rng, &mut seed[..]).map_err(|_| "coin randomness")?;
        Ok((*seed, Self { context, commitment, seed }))
    }

    pub(super) fn open(self, opening: &[u8], frozen_prefix: [u8; 32]) -> Result<Coefficients> {
        let opening: &[u8; 64] = opening.try_into().map_err(|_| "coin opening length")?;
        if self.context.commitment(opening) != self.commitment {
            return Err("coin opening commitment");
        }
        let seed = std::array::from_fn(|index| self.seed[index] ^ opening[index]);
        Coefficients::new(self.context, frozen_prefix, seed)
    }
}

pub(super) struct Coefficients {
    reader: Shake256Reader,
    prefix: [u8; 32],
    count: u64,
    next: u64,
    work: Work,
}

impl Coefficients {
    fn new(context: Context, prefix: [u8; 32], seed: [u8; 32]) -> Result<Self> {
        if prefix == [0; 32] {
            return Err("coin frozen prefix");
        }
        let mut hash = Shake256::default();
        hash.update(DOMAIN);
        hash.update(b"/coefficients/");
        hash.update(&context.nonce);
        hash.update(&context.prefix);
        hash.update(&[context.phase as u8]);
        hash.update(&prefix);
        hash.update(&context.count.to_le_bytes());
        hash.update(&seed);
        let reader = hash.finalize_xof();
        let work = Work {
            shake_calls: 1,
            absorbed_bytes: (DOMAIN.len() + b"/coefficients/".len() + 137) as u64,
            shake_object_bytes_peak: size_of::<Shake256>().max(size_of_val(&reader)),
            ..Default::default()
        };
        Ok(Self { reader, prefix, count: context.count, next: 0, work })
    }

    pub(super) fn draw(&mut self, prefix: [u8; 32], index: u64) -> Result<Fp3> {
        if prefix != self.prefix || index != self.next || self.next >= self.count {
            self.next = self.count + 1;
            return Err("coin coordinate or prefix");
        }
        let mut tape = [0; 192];
        self.reader.read(&mut tape);
        self.work.squeezed_bytes += tape.len() as u64;
        self.next = self.count + 1;
        let limbs = sample_h_limbs(&tape, &mut self.work).map_err(|_| "coin sampler exhausted")?;
        self.next = index + 1;
        Ok(Fp3::new(limbs[0], limbs[1], limbs[2]))
    }

    pub(super) fn finish(self) -> Result<Work> {
        if self.next != self.count {
            return Err("coin consumption incomplete");
        }
        Ok(self.work)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    pub(in crate::c71_seed6) struct BadRng(pub bool);
    impl CryptoRng for BadRng {}
    impl RngCore for BadRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!()
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), rand::Error> {
            if self.0 {
                return Err(rand::Error::new("unavailable test randomness"));
            }
            bytes.fill(0xff);
            Ok(())
        }
    }

    #[test]
    fn c71_seed6_coin_order_domains_and_fail_closed() {
        let context = Context::new([1; 32], [2; 32], Phase::Split, 4).unwrap();
        for fault in 0..7 {
            let (commitment, committed) =
                Committed::new(context, &mut StdRng::seed_from_u64(1)).unwrap();
            let (mut response, replied) =
                Replied::new(context, &commitment, &mut StdRng::seed_from_u64(2)).unwrap();
            if fault == 6 {
                response[0] ^= 1;
            }
            let (mut opening, mut receiver) = committed.open(&response, [3; 32]).unwrap();
            if fault == 1 {
                opening[0] ^= 1;
            }
            if fault == 2 {
                opening[63] ^= 1;
            }
            let sender = replied.open(&opening, [3; 32]);
            if matches!(fault, 1 | 2) {
                assert!(sender.is_err());
                continue;
            }
            let mut sender = sender.unwrap();
            if fault == 3 {
                assert!(sender.draw([4; 32], 0).is_err());
            }
            if fault == 4 {
                assert!(sender.draw([3; 32], 1).is_err());
            }
            if matches!(fault, 3 | 4) {
                assert!(sender.draw([3; 32], 0).is_err());
                assert!(sender.finish().is_err());
                continue;
            }
            if fault == 5 {
                assert!(sender.finish().is_err());
                continue;
            }
            if fault == 6 {
                assert_ne!(sender.draw([3; 32], 0).unwrap(), receiver.draw([3; 32], 0).unwrap());
                continue;
            }
            for index in 0..4 {
                assert_eq!(sender.draw([3; 32], index), receiver.draw([3; 32], index));
            }
            let work = sender.finish().unwrap();
            assert_eq!(work, receiver.finish().unwrap());
            assert_eq!(work.shake_calls, 1);
            assert_eq!(work.squeezed_bytes, 4 * 192);
        }
        assert!(Committed::new(context, &mut BadRng(true)).is_err());
        assert!(Replied::new(context, &[0; 32], &mut BadRng(true)).is_err());
        assert!(Replied::new(context, &[0; 31], &mut StdRng::seed_from_u64(2)).is_err());
        let (_, committed) = Committed::new(context, &mut StdRng::seed_from_u64(1)).unwrap();
        assert!(committed.open(&[0; 31], [3; 32]).is_err());
        let (_, replied) = Replied::new(context, &[0; 32], &mut StdRng::seed_from_u64(2)).unwrap();
        assert!(replied.open(&[0; 63], [3; 32]).is_err());
        let mut split = Coefficients::new(context, [3; 32], [4; 32]).unwrap();
        let equality = Context::new([1; 32], [2; 32], Phase::Equality, 4).unwrap();
        let mut equality = Coefficients::new(equality, [3; 32], [4; 32]).unwrap();
        assert_ne!(split.draw([3; 32], 0), equality.draw([3; 32], 0));
        assert!(Context::new([0; 32], [2; 32], Phase::Split, 4).is_err());
        assert!(Context::new([1; 32], [2; 32], Phase::Equality, 676).is_err());
        let (commitment, committed) =
            Committed::new(context, &mut StdRng::seed_from_u64(1)).unwrap();
        let wrong = Context::new([1; 32], [2; 32], Phase::Equality, 4).unwrap();
        let (response, replied) =
            Replied::new(wrong, &commitment, &mut StdRng::seed_from_u64(2)).unwrap();
        let (opening, _) = committed.open(&response, [3; 32]).unwrap();
        assert!(replied.open(&opening, [3; 32]).is_err());
    }

    #[test]
    fn c71_seed6_coin_shake_matches_python_stream() {
        let context = Context::new([1; 32], [2; 32], Phase::Split, 4).unwrap();
        let mut coins = Coefficients::new(context, [3; 32], [4; 32]).unwrap();
        let expected = [
            [7834151124423964235, 13031131941374409903, 5681944031133750938],
            [10799003285637748551, 2284425053434151683, 5053289842844629254],
            [521325176319418978, 2348289769777282647, 13570224334304954887],
            [7349065728333141785, 3639344013350648656, 7378902005202314930],
        ];
        for (index, limbs) in expected.into_iter().enumerate() {
            let value = coins.draw([3; 32], index as u64).unwrap();
            assert_eq!([value.c0.value(), value.c1.value(), value.c2.value()], limbs);
        }
        let work = coins.finish().unwrap();
        assert_eq!(work.absorbed_bytes, 173);
        assert_eq!(work.fp_candidates, 12);
        assert_eq!(work.codec_heap_capacity_bytes_peak, 0);
        eprintln!(
            "C71_SEED6_COINS {}",
            serde_json::json!({
                "hash_absorbed_bytes":work.absorbed_bytes,
                "coefficients":4,"XOF_squeezed_bytes":work.squeezed_bytes,
                "Committed_bytes":size_of::<Committed>(),"Replied_bytes":size_of::<Replied>(),
                "Coefficients_bytes":size_of::<Coefficients>(),"heap_bytes":0,
                "SHAKE_object_bytes":work.shake_object_bytes_peak,
                "full_FS_and_seal":false
            })
        );
    }
}

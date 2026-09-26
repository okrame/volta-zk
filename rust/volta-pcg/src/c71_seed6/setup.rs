//! One-channel reduced setup, through accepted EA state. The caller still
//! owes an authenticated channel, non-rollbackable burn and full transcript.
use super::super::{corrections, ProverGuard, VerifierGuard};
use super::{expand, Error};
use crate::c71_bootstrap::{random_bytes, recv, send, Audit, Context};
use crate::c71_seed6::{coins, equality, real};
use rand::{CryptoRng, RngCore};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"VOLTA-C71-Seed6-setup-v1";

#[derive(Clone, Copy)]
struct Geometry {
    blocks: usize,
    height: usize,
    weight: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rejected(_: Error) -> io::Error {
    invalid("guard or cGGM setup rejected")
}

impl Geometry {
    fn contexts(self, context: &Context) -> io::Result<[Context; 2]> {
        if self.blocks == 0
            || self.blocks > 675
            || self.height == 0
            || self.height > 19
            || self.weight == 0
            || self.weight > 11
            || [context.session, context.channel, context.capacity].contains(&[0; 32])
        {
            return Err(invalid("setup geometry or context"));
        }
        let domain = self.blocks << self.height;
        if domain < 5 || self.weight > domain || context.rows != domain / 5 {
            return Err(invalid("setup output capacity"));
        }
        let mut hash = blake3::Hasher::new();
        hash.update(DOMAIN);
        hash.update(b"/geometry/");
        hash.update(&context.capacity);
        for word in [self.blocks, self.height, self.weight, context.rows] {
            hash.update(&(word as u64).to_le_bytes());
        }
        let capacity = *hash.finalize().as_bytes();
        Ok([self.blocks * (self.height + 7) + 3, 3 * self.blocks].map(|rows| Context {
            session: context.session,
            channel: context.channel,
            capacity,
            rows,
        }))
    }
}

fn nonce(main: [u8; 32], inverse: [u8; 32]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(DOMAIN);
    hash.update(b"/sealed-nonce/");
    hash.update(&main);
    hash.update(&inverse);
    *hash.finalize().as_bytes()
}

fn sender(
    mut channel: impl Read + Write,
    context: Context,
    geometry: Geometry,
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<(expand::Sender, [Audit; 3])> {
    let [main_context, inverse_context] = geometry.contexts(&context)?;
    let mut main = real::verifier_with_rng(&mut channel, main_context, 0, rng)?;
    let mut inverse = real::prover_with_rng(&mut channel, inverse_context, 1, rng)?;
    let nonce = nonce(main.binding, inverse.binding);
    let mut audits =
        [std::mem::take(&mut main.audit), std::mem::take(&mut inverse.audit), Audit::default()];
    let audit = &mut audits[2];
    let main = real::reserve_equality_verifier_tail(main, 3 * geometry.blocks)?;
    let wire = recv(&mut channel, 40, 8 * geometry.blocks * (geometry.height + 1), audit)?;
    let corrections =
        wire.chunks_exact(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap())).collect();
    let verifier =
        VerifierGuard::freeze(main.prefix, geometry.blocks, geometry.height, corrections)
            .map_err(rejected)?
            .challenge_bound()
            .map_err(rejected)?;
    drop(wire);
    let proof = recv(&mut channel, 41, 48, audit)?;
    let guard = verifier.verify(&proof).map_err(rejected)?;
    drop(proof);
    let context = coins::Context::new(
        nonce,
        guard.frozen.prefix,
        coins::Phase::Split,
        (geometry.blocks << geometry.height) as u64,
    )
    .map_err(invalid)?;
    let commitment = recv(&mut channel, 42, 32, audit)?;
    let (wire, sender) = guard.cggm(nonce, rng).map_err(rejected)?;
    let (response, replied) = coins::Replied::new(context, &commitment, rng).map_err(invalid)?;
    drop(commitment);
    send(&mut channel, 43, &wire, audit)?;
    send(&mut channel, 44, &response, audit)?;
    drop(wire);
    let opening = recv(&mut channel, 45, 64, audit)?;
    let mut coefficients = replied.open(&opening, sender.prefix).map_err(invalid)?;
    drop(opening);
    let wire = recv(&mut channel, 46, 24 * geometry.blocks, audit)?;
    let sender = sender
        .split(&wire, |prefix, block, leaf| {
            coefficients
                .draw(prefix, ((block as u64) << geometry.height) + leaf)
                .map_err(|_| Error::Rejected)
        })
        .map_err(rejected)?;
    coefficients.finish().map_err(invalid)?;
    drop(wire);
    let equality =
        equality::Prepared::new(0, nonce, inverse, main.equality_tail, sender.values, sender.state)
            .map_err(invalid)?;
    let accepted = equality.exchange(&mut channel, rng, audit)?;
    Ok((expand::Sender::new(accepted, geometry.weight).map_err(rejected)?, audits))
}

fn receiver(
    mut channel: impl Read + Write,
    context: Context,
    geometry: Geometry,
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<(expand::Receiver, [Audit; 3])> {
    let [main_context, inverse_context] = geometry.contexts(&context)?;
    let mut main = real::prover_with_rng(&mut channel, main_context, 0, rng)?;
    let mut inverse = real::verifier_with_rng(&mut channel, inverse_context, 1, rng)?;
    let nonce = nonce(main.binding, inverse.binding);
    let mut audits =
        [std::mem::take(&mut main.audit), std::mem::take(&mut inverse.audit), Audit::default()];
    let audit = &mut audits[2];
    let main = real::reserve_equality_prover_tail(main, 3 * geometry.blocks)?;
    let mut paths = Zeroizing::new(Vec::with_capacity(geometry.blocks));
    let mut betas = Zeroizing::new(Vec::with_capacity(geometry.blocks));
    for block in 0..geometry.blocks {
        let mut bytes = Zeroizing::new([0; 8]);
        random_bytes(rng, &mut *bytes)?;
        paths.push(u64::from_le_bytes(*bytes) & ((1 << geometry.height) - 1));
        betas.push(main.prefix.values[block * (geometry.height + 4)]);
    }
    let corrections =
        corrections(&main.prefix, geometry.height, &betas, &paths).map_err(rejected)?;
    drop(betas);
    let mut wire = Vec::with_capacity(8 * corrections.len());
    for value in &corrections {
        wire.extend_from_slice(&value.to_le_bytes());
    }
    send(&mut channel, 40, &wire, audit)?;
    drop(wire);
    let guard = ProverGuard::freeze(main.prefix, geometry.blocks, geometry.height, corrections)
        .map_err(rejected)?;
    let context = coins::Context::new(
        nonce,
        guard.frozen.prefix,
        coins::Phase::Split,
        (geometry.blocks << geometry.height) as u64,
    )
    .map_err(invalid)?;
    let (proof, guard) = guard.prove_bound().map_err(rejected)?;
    send(&mut channel, 41, &proof, audit)?;
    let (commitment, committed) = coins::Committed::new(context, rng).map_err(invalid)?;
    send(&mut channel, 42, &commitment, audit)?;
    let wire = recv(&mut channel, 43, 24 * geometry.blocks * geometry.height, audit)?;
    let receiver = guard.cggm(nonce, std::mem::take(&mut *paths), &wire).map_err(rejected)?;
    drop(wire);
    let response = recv(&mut channel, 44, 32, audit)?;
    let (opening, mut coefficients) =
        committed.open(&response, receiver.prefix).map_err(invalid)?;
    drop(response);
    send(&mut channel, 45, &opening, audit)?;
    let (wire, receiver) = receiver
        .split(|prefix, block, leaf| {
            coefficients
                .draw(prefix, ((block as u64) << geometry.height) + leaf)
                .map_err(|_| Error::Rejected)
        })
        .map_err(rejected)?;
    coefficients.finish().map_err(invalid)?;
    send(&mut channel, 46, &wire, audit)?;
    drop(wire);
    let equality = equality::Prepared::new(
        1,
        nonce,
        main.equality_tail,
        inverse,
        receiver.values,
        receiver.state,
    )
    .map_err(invalid)?;
    let accepted = equality.exchange(&mut channel, rng, audit)?;
    Ok((expand::Receiver::new(accepted, geometry.weight).map_err(rejected)?, audits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{os::unix::net::UnixStream, thread, time::Duration};
    use volta_field::{Fp, Fp3};

    fn context() -> Context {
        Context { session: [1; 32], channel: [2; 32], capacity: [3; 32], rows: 6 }
    }

    #[test]
    fn c71_seed6_one_channel_setup_to_original_ea_macs() {
        let geometry = Geometry { blocks: 2, height: 4, weight: 2 };
        let (left, right) = UnixStream::pair().unwrap();
        for stream in [&left, &right] {
            stream.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let peer = thread::spawn(move || {
            receiver(right, context(), geometry, &mut StdRng::seed_from_u64(901)).unwrap()
        });
        let (mut sender, sender_audits) =
            sender(left, context(), geometry, &mut StdRng::seed_from_u64(902)).unwrap();
        let (mut receiver, receiver_audits) = peer.join().unwrap();
        assert_eq!(sender.binding, receiver.binding);
        for row in 0..6 {
            let key = sender.next_row().unwrap();
            let value = receiver.next_row().unwrap();
            let key = Fp3::new(Fp::new(key[0]), Fp::new(key[1]), Fp::new(key[2]));
            let tag = Fp3::new(Fp::new(value[1]), Fp::new(value[2]), Fp::new(value[3]));
            assert_eq!(tag, key + sender.delta().mul_base(Fp::new(value[0])), "row {row}");
        }
        assert!(sender.next_row().is_err());
        assert!(receiver.next_row().is_err());
        let mut wire = 0;
        for (sender, receiver) in sender_audits.iter().zip(&receiver_audits) {
            assert_eq!(sender.sent_frames, receiver.received_frames);
            assert_eq!(receiver.sent_frames, sender.received_frames);
            wire += sender
                .sent_frames
                .iter()
                .chain(&sender.received_frames)
                .map(|(_, bytes)| bytes)
                .sum::<usize>();
        }
        assert_eq!(wire, 390742);
        for (role, audits) in [("sender", &sender_audits), ("receiver", &receiver_audits)] {
            let bytes: [usize; 3] = std::array::from_fn(|index| {
                let audit = &audits[index];
                (audit.sent_frames.capacity() + audit.received_frames.capacity())
                    * size_of::<(u8, usize)>()
                    + audit.phase_seconds.capacity() * size_of::<(&str, f64)>()
            });
            assert_eq!(bytes, [256, 256, 384]);
            assert_eq!(size_of::<[Audit; 3]>(), 672);
            println!(
                "C71_SEED6_SETUP_AUDIT role={role} heap_bytes={bytes:?} native_value_bytes={}",
                size_of::<[Audit; 3]>()
            );
        }
        println!("C71_SEED6_ONE_CHANNEL main_rows=25 inverse_rows=6 base_rows=6 wire_bytes={wire} fresh_paths=true beta_from_original_seed=true durable_burn=false");
    }

    #[test]
    fn c71_seed6_one_channel_geometry_rejects_before_io_or_rng() {
        for geometry in [
            Geometry { blocks: 0, height: 4, weight: 2 },
            Geometry { blocks: 2, height: 20, weight: 2 },
            Geometry { blocks: 2, height: 4, weight: 12 },
            Geometry { blocks: 1, height: 4, weight: 2 },
        ] {
            let error = sender(
                std::io::Cursor::new(Vec::<u8>::new()),
                context(),
                geometry,
                &mut coins::tests::BadRng(true),
            )
            .err()
            .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn c71_seed6_one_channel_binds_geometry_before_ot() {
        let (left, right) = UnixStream::pair().unwrap();
        for stream in [&left, &right] {
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        }
        let peer = thread::spawn(move || {
            receiver(
                right,
                context(),
                Geometry { blocks: 2, height: 4, weight: 3 },
                &mut StdRng::seed_from_u64(903),
            )
            .err()
            .unwrap()
        });
        let error = sender(
            left,
            context(),
            Geometry { blocks: 2, height: 4, weight: 2 },
            &mut StdRng::seed_from_u64(904),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "context mismatch");
        assert_eq!(peer.join().unwrap().kind(), io::ErrorKind::UnexpectedEof);
    }
}

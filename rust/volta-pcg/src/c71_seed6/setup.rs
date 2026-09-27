//! One-channel reduced setup, through accepted EA state. The caller still
//! owns the authenticated channel and non-rollbackable store. The one-use
//! entry burns setup before RNG; attempt windows burn before row generation.
//! NoPeek preparation and complete verifier acceptance remain caller duties.
use super::super::{corrections, ProverGuard, VerifierGuard};
use super::{expand, Error};
use crate::c71_bootstrap::{random_bytes, recv, send, Audit, Context};
use crate::c71_lifetime::{Attempt, Lifetime, ModelBinding};
use crate::c71_seed6::{coins, equality, real};
use rand::{CryptoRng, RngCore};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"VOLTA-C71-Seed6-setup-v1";

#[derive(Clone, Copy)]
pub struct Geometry {
    blocks: usize,
    height: usize,
    weight: usize,
}

pub struct ProverPool<'lifetime>(Once<'lifetime, expand::Receiver>);
pub struct VerifierPool<'lifetime>(Once<'lifetime, expand::Sender>);

pub fn prover<'lifetime>(
    store: &'lifetime mut Lifetime,
    channel: impl Read + Write,
    session: [u8; 32],
    binding: [u8; 32],
    geometry: Geometry,
) -> io::Result<ProverPool<'lifetime>> {
    receiver_once(store, channel, session, binding, geometry, &mut rand::rngs::OsRng)
        .map(ProverPool)
}

pub fn verifier<'lifetime>(
    store: &'lifetime mut Lifetime,
    channel: impl Read + Write,
    session: [u8; 32],
    binding: [u8; 32],
    geometry: Geometry,
) -> io::Result<VerifierPool<'lifetime>> {
    sender_once(store, channel, session, binding, geometry, &mut rand::rngs::OsRng)
        .map(VerifierPool)
}

impl ProverPool<'_> {
    pub fn fixed_run_context(&self) -> io::Result<(ModelBinding, [u8; 32], Attempt)> {
        self.0.fixed_run_context()
    }

    pub fn remaining_fp3(&self) -> usize {
        self.0.store.remaining_fp3()
    }

    pub fn audits(&self) -> &[Audit; 3] {
        &self.0.audits
    }

    pub fn stop(&mut self) {
        self.0.stop();
    }

    pub fn attempt<Value>(
        &mut self,
        full_fp3: usize,
        consumer: impl FnOnce(
            Attempt,
            &mut dyn Iterator<Item = io::Result<Zeroizing<[u64; 4]>>>,
        ) -> io::Result<(Value, Option<[u8; 32]>)>,
    ) -> io::Result<Value> {
        self.0.attempt(full_fp3, consumer)
    }
}

impl VerifierPool<'_> {
    pub fn fixed_run_context(&self) -> io::Result<(ModelBinding, [u8; 32], Attempt)> {
        self.0.fixed_run_context()
    }

    pub fn remaining_fp3(&self) -> usize {
        self.0.store.remaining_fp3()
    }

    pub fn audits(&self) -> &[Audit; 3] {
        &self.0.audits
    }

    pub fn stop(&mut self) {
        self.0.stop();
    }

    pub fn attempt<Value>(
        &mut self,
        full_fp3: usize,
        consumer: impl FnOnce(
            Attempt,
            &mut dyn Iterator<Item = io::Result<Zeroizing<[u64; 3]>>>,
            volta_field::Fp3,
        ) -> io::Result<(Value, Option<[u8; 32]>)>,
    ) -> io::Result<Value> {
        self.0.attempt(full_fp3, consumer)
    }
}

struct Once<'lifetime, State> {
    store: &'lifetime mut Lifetime,
    session: [u8; 32],
    capacity: [u8; 32],
    state: Option<State>,
    audits: [Audit; 3],
}

impl<State> Once<'_, State> {
    fn fixed_run_context(&self) -> io::Result<(ModelBinding, [u8; 32], Attempt)> {
        if self.state.is_none() {
            return Err(invalid("no live Seed6 state"));
        }
        self.store.fixed_run_context(self.session, self.capacity)
    }

    fn stop(&mut self) {
        self.store.stop();
        self.state.take();
    }

    fn consume<const WIDTH: usize, Value>(
        &mut self,
        full_fp3: usize,
        next_batch: fn(&mut State, usize) -> Result<Zeroizing<Vec<[u64; WIDTH]>>, Error>,
        consumer: impl FnOnce(
            Attempt,
            &mut dyn Iterator<Item = io::Result<Zeroizing<[u64; WIDTH]>>>,
        ) -> io::Result<(Value, Option<[u8; 32]>)>,
    ) -> io::Result<Value> {
        let state = self.state.as_mut().ok_or_else(|| invalid("no live Seed6 state"))?;
        let result = self.store.attempt(self.capacity, full_fp3, |attempt, count| {
            let mut remaining = count;
            let mut failed = false;
            let mut batch = Zeroizing::new(Vec::new());
            let mut cursor = 0;
            let mut rows = std::iter::from_fn(|| {
                if remaining == 0 || failed {
                    return None;
                }
                if cursor == batch.len() {
                    batch = Zeroizing::new(Vec::new());
                    let take = remaining.min(expand::BATCH);
                    match next_batch(state, take) {
                        Ok(values) if values.len() == take => batch = values,
                        _ => {
                            failed = true;
                            return Some(Err(invalid("Seed6 batch generation failed")));
                        }
                    }
                    cursor = 0;
                }
                let value = Zeroizing::new(std::mem::replace(&mut batch[cursor], [0; WIDTH]));
                cursor += 1;
                remaining -= 1;
                Some(Ok(value))
            });
            let result = consumer(attempt, &mut rows)?;
            if failed || remaining != 0 {
                return Err(invalid("incomplete or failed Seed6 reservation"));
            }
            Ok(result)
        });
        if result.is_err() || self.fixed_run_context().is_err() {
            self.stop();
        }
        result
    }
}

impl Once<'_, expand::Sender> {
    fn attempt<Value>(
        &mut self,
        full_fp3: usize,
        consumer: impl FnOnce(
            Attempt,
            &mut dyn Iterator<Item = io::Result<Zeroizing<[u64; 3]>>>,
            volta_field::Fp3,
        ) -> io::Result<(Value, Option<[u8; 32]>)>,
    ) -> io::Result<Value> {
        let delta = self.state.as_ref().ok_or_else(|| invalid("no live Seed6 state"))?.delta();
        self.consume(full_fp3, expand::Sender::next_batch, |attempt, rows| {
            consumer(attempt, rows, delta)
        })
    }
}

impl Once<'_, expand::Receiver> {
    fn attempt<Value>(
        &mut self,
        full_fp3: usize,
        consumer: impl FnOnce(
            Attempt,
            &mut dyn Iterator<Item = io::Result<Zeroizing<[u64; 4]>>>,
        ) -> io::Result<(Value, Option<[u8; 32]>)>,
    ) -> io::Result<Value> {
        self.consume(full_fp3, expand::Receiver::next_batch, consumer)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rejected(_: Error) -> io::Error {
    invalid("guard or cGGM setup rejected")
}

impl Geometry {
    pub fn new(blocks: usize, height: usize, weight: usize) -> io::Result<Self> {
        let geometry = Self { blocks, height, weight };
        if geometry.capacity()? % 3 != 0 {
            return Err(invalid("incomplete Fp3 capacity"));
        }
        Ok(geometry)
    }

    pub fn capacity(self) -> io::Result<usize> {
        if self.blocks == 0
            || self.blocks > 675
            || self.height == 0
            || self.height > 19
            || self.weight == 0
            || self.weight > 11
        {
            return Err(invalid("setup geometry"));
        }
        let domain = self.blocks << self.height;
        if domain < 5 || self.weight > domain {
            return Err(invalid("setup domain"));
        }
        Ok(domain / 5)
    }

    fn contexts(self, context: &Context) -> io::Result<[Context; 2]> {
        if [context.session, context.channel, context.capacity].contains(&[0; 32]) {
            return Err(invalid("setup geometry or context"));
        }
        if context.rows != self.capacity()? {
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

fn sender_once<'lifetime>(
    store: &'lifetime mut Lifetime,
    channel: impl Read + Write,
    session: [u8; 32],
    binding: [u8; 32],
    geometry: Geometry,
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<Once<'lifetime, expand::Sender>> {
    let context = store.begin_seed6(session, binding, geometry.capacity()?)?;
    let (state, audits) = sender(channel, context, geometry, rng)?;
    Ok(Once { store, session, capacity: state.binding, state: Some(state), audits })
}

fn receiver_once<'lifetime>(
    store: &'lifetime mut Lifetime,
    channel: impl Read + Write,
    session: [u8; 32],
    binding: [u8; 32],
    geometry: Geometry,
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<Once<'lifetime, expand::Receiver>> {
    let context = store.begin_seed6(session, binding, geometry.capacity()?)?;
    let (state, audits) = receiver(channel, context, geometry, rng)?;
    Ok(Once { store, session, capacity: state.binding, state: Some(state), audits })
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
    use crate::c71_lifetime::ModelBinding;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{os::unix::net::UnixStream, thread, time::Duration};
    use volta_field::{Fp, Fp3};

    fn model() -> ModelBinding {
        ModelBinding { anchor: [1; 32], semantics: [2; 32], root: [3; 32] }
    }

    fn journal_path(role: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "c71-seed6-{role}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

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

    #[test]
    fn c71_seed6_journal_burns_before_rng_and_cannot_retry_or_reopen() {
        let path = journal_path("failure");
        let mut store = Lifetime::install(&path, model()).unwrap();
        let geometry = Geometry { blocks: 2, height: 4, weight: 2 };
        for rows in [0, 1, 70_778_883] {
            assert!(store.begin_seed6([1; 32], [2; 32], rows).is_err());
            assert_eq!(store.counters(), (0, 0));
        }
        let error = sender_once(
            &mut store,
            std::io::Cursor::new(Vec::<u8>::new()),
            [1; 32],
            [2; 32],
            geometry,
            &mut coins::tests::BadRng(true),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "OS randomness unavailable");
        assert_eq!(store.counters(), (1, 0));
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 104 + 57);
        assert_eq!(bytes[104], 5);
        assert_eq!(u64::from_le_bytes(bytes[121..129].try_into().unwrap()), 6);
        assert!(store.begin_seed6([1; 32], [2; 32], 6).is_err());
        assert!(store
            .prover_fixed_run(std::io::Cursor::new(Vec::<u8>::new()), [1; 32], [2; 32], 3)
            .is_err());
        assert!(store.prover(std::io::Cursor::new(Vec::<u8>::new()), [1; 32], [2; 32], 3).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        drop(store);
        assert!(Lifetime::open(&path, model()).is_err());
        assert!(Lifetime::install(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn c71_seed6_journal_real_setup_owns_the_live_lifetime() {
        let geometry = Geometry { blocks: 2, height: 4, weight: 2 };
        let (left, right) = UnixStream::pair().unwrap();
        for stream in [&left, &right] {
            stream.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let peer = thread::spawn(move || {
            let path = journal_path("receiver");
            let mut store = Lifetime::install(&path, model()).unwrap();
            let output = {
                let mut setup = receiver_once(
                    &mut store,
                    right,
                    [1; 32],
                    [2; 32],
                    geometry,
                    &mut StdRng::seed_from_u64(905),
                )
                .unwrap();
                assert_eq!(setup.store.counters(), (1, 0));
                assert_eq!(
                    setup.audits[2].sent_frames.len() + setup.audits[2].received_frames.len(),
                    16
                );
                let mut rows = Vec::new();
                for ordinal in 1..=2 {
                    assert_eq!(setup.fixed_run_context().unwrap().2.ordinal, ordinal);
                    setup
                        .attempt(1, |attempt, reserved| {
                            assert_eq!(attempt.first_base_row, 3 * (ordinal - 1));
                            rows.extend(reserved.map(|row| *row.unwrap()));
                            Ok(((), Some([ordinal as u8 + 10; 32])))
                        })
                        .unwrap();
                }
                assert_eq!(setup.store.counters(), (1, 2));
                assert_eq!(setup.store.remaining_fp3(), 0);
                assert_eq!(setup.store.accepted_head(), [12; 32]);
                assert!(setup.attempt::<()>(1, |_, _| panic!("exhausted pool used")).is_err());
                assert!(setup.state.is_none());
                (setup.capacity, rows)
            };
            assert!(store.begin_seed6([1; 32], [2; 32], 6).is_err());
            drop(store);
            assert!(Lifetime::open(&path, model()).is_err());
            std::fs::remove_file(path).unwrap();
            output
        });
        let path = journal_path("sender");
        let mut store = Lifetime::install(&path, model()).unwrap();
        {
            let mut setup = sender_once(
                &mut store,
                left,
                [1; 32],
                [2; 32],
                geometry,
                &mut StdRng::seed_from_u64(906),
            )
            .unwrap();
            assert_eq!(setup.store.counters(), (1, 0));
            let (binding, rows) = peer.join().unwrap();
            assert_eq!(setup.capacity, binding);
            for (index, rows) in rows.chunks_exact(3).enumerate() {
                setup
                    .attempt(1, |attempt, reserved, delta| {
                        assert_eq!(attempt.first_base_row, 3 * index as u64);
                        for row in rows {
                            let key = reserved.next().unwrap().unwrap();
                            let key = Fp3::new(Fp::new(key[0]), Fp::new(key[1]), Fp::new(key[2]));
                            let tag = Fp3::new(Fp::new(row[1]), Fp::new(row[2]), Fp::new(row[3]));
                            assert_eq!(tag, key + delta.mul_base(Fp::new(row[0])));
                        }
                        assert!(reserved.next().is_none());
                        Ok(((), Some([index as u8 + 11; 32])))
                    })
                    .unwrap();
            }
            assert_eq!(setup.store.counters(), (1, 2));
            assert_eq!(setup.store.accepted_head(), [12; 32]);
            assert!(setup.attempt::<()>(1, |_, _, _| panic!("exhausted pool used")).is_err());
            assert!(setup.state.is_none());
        }
        assert!(store.begin_seed6([1; 32], [2; 32], 6).is_err());
        drop(store);
        assert!(Lifetime::open(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
        println!("C71_SEED6_JOURNAL record_kind=5 burn_before_RNG=true one_live_owner=true no_retry_or_reopen=true base_rows=6 per_attempt_pool=true acceptance_fixture=true proof=false");
    }

    #[test]
    fn c71_seed6_attempt_window_burns_then_streams_and_stops_on_every_failure() {
        for fault in 0..10 {
            let path = journal_path("attempt-failure");
            let mut store = Lifetime::install(&path, model()).unwrap();
            let context = store.begin_seed6([1; 32], [2; 32], 6).unwrap();
            {
                let mut setup = Once {
                    store: &mut store,
                    session: context.session,
                    capacity: context.capacity,
                    state: Some(0usize),
                    audits: Default::default(),
                };
                let count = match fault {
                    4 => 0,
                    5 => 3,
                    6 => usize::MAX,
                    _ => 2,
                };
                let next: fn(&mut usize, usize) -> Result<Zeroizing<Vec<[u64; 1]>>, Error> =
                    if fault == 7 {
                        |_, _| Err(Error::Rejected)
                    } else if fault == 9 {
                        |_, _| Ok(Zeroizing::new(Vec::new()))
                    } else {
                        |cursor: &mut usize, count| {
                            Ok(Zeroizing::new(
                                (0..count)
                                    .map(|_| {
                                        *cursor += 1;
                                        [*cursor as u64]
                                    })
                                    .collect(),
                            ))
                        }
                    };
                let result = setup.consume(count, next, |attempt, rows| {
                    assert_eq!((attempt.ordinal, attempt.first_base_row), (1, 0));
                    let bytes = std::fs::read(&path).unwrap();
                    assert_eq!(bytes.len(), 104 + 2 * 57);
                    assert_eq!(bytes[161], 2);
                    assert_eq!(u64::from_le_bytes(bytes[178..186].try_into().unwrap()), 6);
                    match fault {
                        0 => {
                            rows.next().unwrap()?;
                            Ok(((), Some([9; 32])))
                        }
                        1 => Err(invalid("consumer error")),
                        2 => panic!("consumer panic"),
                        3 | 8 => {
                            for row in rows {
                                row?;
                            }
                            Ok(((), if fault == 3 { None } else { Some([0; 32]) }))
                        }
                        7 | 9 => {
                            assert!(rows.next().unwrap().is_err());
                            assert!(rows.next().is_none());
                            Ok(((), Some([9; 32])))
                        }
                        _ => panic!("invalid capacity reached consumer"),
                    }
                });
                assert_eq!(result.is_ok(), fault == 3);
                assert_eq!(setup.store.counters(), (1, u64::from(![4, 5, 6].contains(&fault))));
                assert_eq!(setup.store.accepted_head(), [0; 32]);
                assert_eq!(setup.store.remaining_fp3(), 0);
                assert!(setup.state.is_none());
                assert!(setup.fixed_run_context().is_err());
                assert!(setup
                    .consume::<1, ()>(
                        1,
                        |_, _| panic!("stopped state generated rows"),
                        |_, _| panic!("stopped state reached consumer")
                    )
                    .is_err());
            }
            drop(store);
            assert!(Lifetime::open(&path, model()).is_err());
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn c71_seed6_attempt_window_three_disjoint_intervals_and_durable_heads() {
        let path = journal_path("attempt-success");
        let mut store = Lifetime::install(&path, model()).unwrap();
        let context = store.begin_seed6([1; 32], [2; 32], 9).unwrap();
        {
            let mut setup = Once {
                store: &mut store,
                session: context.session,
                capacity: context.capacity,
                state: Some(0usize),
                audits: Default::default(),
            };
            for ordinal in 1..=3 {
                let next = setup.fixed_run_context().unwrap().2;
                assert_eq!((next.ordinal, next.first_base_row), (ordinal, 3 * (ordinal - 1)));
                assert_eq!(next.predecessor, [ordinal as u8 - 1; 32]);
                setup
                    .consume(
                        1,
                        |cursor, count| {
                            Ok(Zeroizing::new(
                                (0..count)
                                    .map(|_| {
                                        let row = *cursor;
                                        *cursor += 1;
                                        [row as u64]
                                    })
                                    .collect(),
                            ))
                        },
                        |attempt, rows| {
                            assert_eq!(attempt.ordinal, ordinal);
                            for index in 0..3 {
                                assert_eq!(*rows.next().unwrap()?, [3 * (ordinal - 1) + index]);
                            }
                            assert!(rows.next().is_none());
                            Ok(((), Some([ordinal as u8; 32])))
                        },
                    )
                    .unwrap();
                assert_eq!(setup.store.accepted_head(), [ordinal as u8; 32]);
                let bytes = std::fs::read(&path).unwrap();
                assert_eq!(bytes.len(), 104 + (1 + 2 * ordinal as usize) * 57);
                assert_eq!(&bytes[bytes.len() - 32..], &[ordinal as u8; 32]);
            }
            assert!(setup.state.is_none());
            assert!(setup.fixed_run_context().is_err());
        }
        drop(store);
        assert!(Lifetime::open(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
        println!("C71_SEED6_ATTEMPTS base_rows=9 disjoint_attempts=3 full_reservation_materialized=false batch_cap=4096 row_generated_after_burn=true acceptance_fixture=true proof=false");
    }

    #[test]
    fn c71_seed6_attempt_window_never_prefetches_the_next_reservation() {
        let path = journal_path("batch-boundary");
        let mut store = Lifetime::install(&path, model()).unwrap();
        let context = store.begin_seed6([1; 32], [2; 32], 4104).unwrap();
        {
            let mut setup = Once {
                store: &mut store,
                session: context.session,
                capacity: context.capacity,
                state: Some((0usize, Vec::<usize>::new())),
                audits: Default::default(),
            };
            for (ordinal, count) in [(1, 1367), (2, 1)] {
                setup
                    .consume(
                        count,
                        |(cursor, batches), count| {
                            batches.push(count);
                            Ok(Zeroizing::new(
                                (0..count)
                                    .map(|_| {
                                        let row = *cursor;
                                        *cursor += 1;
                                        [row as u64]
                                    })
                                    .collect(),
                            ))
                        },
                        |attempt, rows| {
                            for index in 0..3 * count {
                                assert_eq!(
                                    *rows.next().unwrap()?,
                                    [attempt.first_base_row + index as u64]
                                );
                            }
                            assert!(rows.next().is_none());
                            Ok(((), Some([ordinal; 32])))
                        },
                    )
                    .unwrap();
                let (cursor, batches) = setup.state.as_ref().unwrap();
                if ordinal == 1 {
                    assert_eq!((*cursor, batches.as_slice()), (4101, [4096, 5].as_slice()));
                } else {
                    assert_eq!((*cursor, batches.as_slice()), (4104, [4096, 5, 3].as_slice()));
                }
            }
        }
        drop(store);
        assert!(Lifetime::open(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

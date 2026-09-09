//! B12: one installed model/root, durable burns, volatile B11 pools.
//!
//! Component only. The honest role must own one non-rollbackable store for
//! the model lifetime and supply an authenticated channel. Root renewal is
//! unavailable until a concrete same-W proof exists. A successful consumer
//! must verify the complete relation before returning an accepted digest.
//! No filesystem journal proves that cryptographic premise or NoPeek.

use crate::c71_bootstrap::{self, Audit, Context};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: u64 = 1 << 20;
const ROOT_SLOTS: u64 = 3; // B2's finite exposure profile, not a PCS privacy theorem.
const RECORD: usize = 57;
type Digest = [u8; 32];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Public identity only: no W or Delta in model installation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModelBinding {
    pub anchor: Digest,
    pub semantics: Digest,
    pub root: Digest,
}

impl ModelBinding {
    fn bytes(self) -> io::Result<Vec<u8>> {
        if [self.anchor, self.semantics, self.root].contains(&[0; 32]) {
            return Err(invalid("zero model identity"));
        }
        Ok([b"C71B12v1".as_slice(), &self.anchor, &self.semantics, &self.root].concat())
    }
}

#[derive(Default, Clone, Copy)]
struct State {
    setups: u64,
    attempts: u64,
    rows: u64,
    used: u64,
    pending: bool,
    head: Digest,
}

impl State {
    fn apply(&mut self, record: &[u8; RECORD]) -> io::Result<()> {
        let word = |i| u64::from_le_bytes(record[i..i + 8].try_into().unwrap());
        let (setup, start, count) = (word(1), word(9), word(17));
        let digest: Digest = record[25..].try_into().unwrap();
        match record[0] {
            1 if self.setups < LIMIT
                && self.attempts < ROOT_SLOTS
                && setup == self.setups + 1
                && start == 0
                && (3..=207).contains(&count)
                && count % 3 == 0
                && digest == [0; 32] =>
            {
                self.setups = setup;
                self.rows = count;
                self.used = 0;
                self.pending = false;
            }
            2 if setup == self.setups
                && setup > 0
                && start == self.used
                && count > 0
                && count % 3 == 0
                && count <= self.rows - self.used
                && self.attempts < LIMIT
                && self.attempts < ROOT_SLOTS
                && digest == self.head =>
            {
                self.used += count;
                self.attempts += 1;
                self.pending = true;
            }
            3 if setup == self.setups
                && self.pending
                && start == self.attempts
                && count == 0
                && digest != self.head
                && digest != [0; 32] =>
            {
                self.head = digest;
                self.pending = false;
            }
            _ => return Err(invalid("invalid lifetime transition")),
        }
        Ok(())
    }
}

/// Holds an OS file lock until drop; concurrent processes fail closed.
/// No Clone, reset, alternate-root, pool serialization or resume API.
pub struct Lifetime {
    file: File,
    model: ModelBinding,
    state: State,
    poisoned: bool,
}

impl Lifetime {
    /// Explicit first installation. An existing file, even empty, is rejected.
    pub fn install(path: &Path, model: ModelBinding) -> io::Result<Self> {
        let bytes = model.bytes()?;
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock().map_err(io::Error::other)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?
            .sync_all()?;
        Ok(Self { file, model, state: State::default(), poisoned: false })
    }

    /// Reopen existing state only; any malformed/truncated record stops use.
    pub fn open(path: &Path, model: ModelBinding) -> io::Result<Self> {
        let expected = model.bytes()?;
        let mut file = OpenOptions::new().read(true).append(true).open(path)?;
        file.try_lock().map_err(io::Error::other)?;
        let mut header = vec![0; expected.len()];
        file.read_exact(&mut header)?;
        if header != expected {
            return Err(invalid("installed model/root mismatch"));
        }
        let mut state = State::default();
        // ponytail: linear replay, at most (2^20 + 6) tiny records in this
        // fixed-root profile; add a verified checkpoint only if reopen cost matters.
        loop {
            let mut record = [0; RECORD];
            if file.read(&mut record[..1])? == 0 {
                break;
            }
            file.read_exact(&mut record[1..])?;
            state.apply(&record)?;
        }
        file.sync_all()?;
        state.pending = false; // no pending acceptance or secret pool survives a restart
        Ok(Self { file, model, state, poisoned: false })
    }

    fn append(
        &mut self,
        kind: u8,
        setup: u64,
        start: u64,
        count: u64,
        digest: Digest,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("lifetime store poisoned"));
        }
        let mut record = [0; RECORD];
        record[0] = kind;
        record[1..9].copy_from_slice(&setup.to_le_bytes());
        record[9..17].copy_from_slice(&start.to_le_bytes());
        record[17..25].copy_from_slice(&count.to_le_bytes());
        record[25..].copy_from_slice(&digest);
        let mut next = self.state;
        next.apply(&record)?;
        self.poisoned = true; // retain poison after partial IO or sync failure
        self.file.write_all(&record)?;
        self.file.sync_all()?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    pub fn counters(&self) -> (u64, u64) {
        (self.state.setups, self.state.attempts)
    }
    pub fn accepted_head(&self) -> Digest {
        self.state.head
    }

    fn begin(&mut self, session: Digest, channel: Digest, rows: usize) -> io::Result<Context> {
        if session == [0; 32] || channel == [0; 32] || self.state.attempts >= ROOT_SLOTS {
            return Err(invalid("invalid channel/session or exhausted installed root"));
        }
        let setup = self.state.setups + 1;
        self.append(1, setup, 0, rows as u64, [0; 32])?; // before RNG/header/OT
        let mut hash = blake3::Hasher::new();
        hash.update(b"C71B12/capacity/");
        hash.update(&self.model.bytes()?);
        hash.update(&session);
        hash.update(&channel);
        hash.update(&setup.to_le_bytes());
        Ok(Context { session, channel, capacity: *hash.finalize().as_bytes(), rows })
    }

    pub fn prover(
        &mut self,
        channel: impl Read + Write,
        session: Digest,
        binding: Digest,
        rows: usize,
    ) -> io::Result<Pool<'_, [u64; 4]>> {
        let context = self.begin(session, binding, rows)?;
        let capacity = context.capacity;
        let output = c71_bootstrap::prover_aes(channel, context)?;
        let data = output
            .values
            .iter()
            .zip(output.tags.iter())
            .map(|(&x, t)| [x, t[0], t[1], t[2]])
            .collect();
        Ok(Pool {
            store: self,
            capacity,
            rows: Zeroizing::new(data),
            delta: None,
            audit: output.audit,
        })
    }

    pub fn verifier(
        &mut self,
        channel: impl Read + Write,
        session: Digest,
        binding: Digest,
        rows: usize,
    ) -> io::Result<Pool<'_, [u64; 3]>> {
        let context = self.begin(session, binding, rows)?;
        let capacity = context.capacity;
        let output = c71_bootstrap::verifier_aes(channel, context)?;
        Ok(Pool {
            store: self,
            capacity,
            rows: output.keys,
            delta: Some(output.delta),
            audit: output.audit,
        })
    }
}

/// Base rows have not been mixed across epochs. Every three consecutive rows
/// pack one Fp3; the native consumer must use Delta_native = -Delta_B11.
pub struct Pool<'a, R: Zeroize + Copy> {
    store: &'a mut Lifetime,
    capacity: Digest,
    rows: Zeroizing<Vec<R>>,
    delta: Option<Zeroizing<[u64; 3]>>,
    pub audit: Audit,
}

pub struct Attempt {
    pub capacity: Digest,
    pub setup: u64,
    pub ordinal: u64,
    pub predecessor: Digest,
    pub first_base_row: u64,
}

impl<R: Zeroize + Copy> Pool<'_, R> {
    /// Burn the root exposure slot and entire typed row interval together.
    /// The callback's plaintexts must obey NoPeek. Some(digest) is permitted
    /// only after the full verifier has accepted PCS/GKR/same-W/state checks;
    /// that verifier is not supplied by this lifecycle component.
    pub fn attempt<T>(
        &mut self,
        full_fp3: usize,
        consumer: impl FnOnce(
            Attempt,
            Zeroizing<Vec<R>>,
            Option<&[u64; 3]>,
        ) -> io::Result<(T, Option<Digest>)>,
    ) -> io::Result<T> {
        let count = full_fp3.checked_mul(3).ok_or_else(|| invalid("row count overflow"))?;
        let state = self.store.state;
        self.store.append(2, state.setups, state.used, count as u64, state.head)?;
        let range = state.used as usize..state.used as usize + count;
        let reserved = Zeroizing::new(self.rows[range.clone()].to_vec());
        for row in &mut self.rows[range] {
            row.zeroize();
        }
        let attempt = Attempt {
            capacity: self.capacity,
            setup: state.setups,
            ordinal: self.store.state.attempts,
            predecessor: state.head,
            first_base_row: state.used,
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            consumer(attempt, reserved, self.delta.as_deref())
        }));
        // Even a caught panic or an IO error must not leave a pending promotion.
        self.store.state.pending = false;
        let (value, accepted) = outcome.map_err(|_| invalid("attempt panicked; burned"))??;
        if let Some(digest) = accepted {
            self.store.state.pending = true;
            let result = self.store.append(3, state.setups, self.store.state.attempts, 0, digest);
            self.store.state.pending = false;
            result?;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ModelBinding {
        ModelBinding { anchor: [1; 32], semantics: [2; 32], root: [3; 32] }
    }

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "c71-b12-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    // Ideal row fixture tests only lifecycle/ownership, never B11 security.
    fn fixture(store: &mut Lifetime, rows: usize) -> Pool<'_, [u64; 4]> {
        let context = store.begin([4; 32], [5; 32], rows).unwrap();
        Pool {
            store,
            capacity: context.capacity,
            rows: Zeroizing::new((0..rows).map(|i| [i as u64; 4]).collect()),
            delta: None,
            audit: Audit::default(),
        }
    }

    #[test]
    fn c71_b12_burns_reopen_model_lock_and_monotone_head() {
        let path = path();
        let mut store = Lifetime::install(&path, model()).unwrap();
        assert!(Lifetime::install(&path, model()).is_err());
        assert!(Lifetime::open(&path, model()).is_err()); // live OS lock
        {
            let mut pool = fixture(&mut store, 9);
            assert!(pool.attempt(0, |_, _, _| Ok(((), None))).is_err());
            assert!(pool.attempt(4, |_, _, _| Ok(((), None))).is_err());
            assert_eq!(pool.store.counters(), (1, 0));
            pool.attempt(1, |a, rows, delta| {
                assert_eq!((a.ordinal, a.first_base_row, a.predecessor), (1, 0, [0; 32]));
                assert_eq!(rows.iter().map(|r| r[0]).collect::<Vec<_>>(), [0, 1, 2]);
                assert!(delta.is_none());
                Ok(((), Some([6; 32]))) // ideal successful verifier fixture
            })
            .unwrap();
            assert_eq!(pool.rows[..3], [[0; 4]; 3]);
            assert_eq!(pool.store.accepted_head(), [6; 32]);
            assert!(pool
                .attempt::<()>(1, |a, rows, _| {
                    assert_eq!((a.ordinal, a.first_base_row, a.predecessor), (2, 3, [6; 32]));
                    assert_eq!(rows[0][0], 3);
                    panic!("consumer failure after emission")
                })
                .is_err());
            assert_eq!(pool.store.counters(), (1, 2));
        } // unused rows lost; no pool resume
        drop(store);
        for changed in [
            ModelBinding { anchor: [7; 32], ..model() },
            ModelBinding { semantics: [7; 32], ..model() },
            ModelBinding { root: [7; 32], ..model() },
        ] {
            assert!(Lifetime::open(&path, changed).is_err());
        }
        let mut store = Lifetime::open(&path, model()).unwrap();
        assert_eq!(store.counters(), (1, 2));
        assert_eq!(store.accepted_head(), [6; 32]);
        {
            let mut pool = fixture(&mut store, 3); // new key epoch, same installed W/root
            assert!(pool
                .attempt::<()>(1, |a, _, _| {
                    assert_eq!((a.setup, a.ordinal, a.predecessor), (2, 3, [6; 32]));
                    Err(invalid("codec failure"))
                })
                .is_err());
        }
        assert!(store.begin([8; 32], [9; 32], 3).is_err()); // new session cannot reset root
        drop(store);
        let store = Lifetime::open(&path, model()).unwrap();
        assert_eq!(store.counters(), (2, 3));
        assert_eq!(store.accepted_head(), [6; 32]);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    struct FailedChannel;
    impl Read for FailedChannel {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(invalid("channel unavailable"))
        }
    }
    impl Write for FailedChannel {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(invalid("channel unavailable"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn c71_b12_setup_failures_and_corrupt_tail_fail_closed() {
        let path = path();
        let mut store = Lifetime::install(&path, model()).unwrap();
        assert!(store.prover(FailedChannel, [4; 32], [5; 32], 3).is_err());
        assert!(store.verifier(FailedChannel, [4; 32], [5; 32], 3).is_err());
        assert_eq!(store.counters(), (2, 0));
        drop(store);
        let store = Lifetime::open(&path, model()).unwrap();
        assert_eq!(store.counters(), (2, 0));
        drop(store);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[1, 0, 0]).unwrap(); // crash during a journal append
        file.sync_all().unwrap();
        drop(file);
        assert!(Lifetime::open(&path, model()).is_err());
        assert!(Lifetime::install(&path, model()).is_err());
        std::fs::remove_file(path).unwrap();
        let mut state = State { setups: LIMIT, ..State::default() };
        let mut record = [0; RECORD];
        record[0] = 1;
        record[1..9].copy_from_slice(&(LIMIT + 1).to_le_bytes());
        record[17..25].copy_from_slice(&3u64.to_le_bytes());
        assert!(state.apply(&record).is_err());
    }

    #[test]
    fn c71_b12_crash_child() {
        let Some(path) = std::env::var_os("C71_B12_CRASH_PATH") else {
            return;
        };
        let mut store = Lifetime::open(Path::new(&path), model()).unwrap();
        fixture(&mut store, 9)
            .attempt::<()>(1, |_, _, _| {
                std::process::exit(17) // no Drop, unwind, ACK or promotion
            })
            .unwrap();
        panic!("crash callback did not run");
    }

    #[test]
    fn c71_b12_process_exit_preserves_burns_and_discards_capacity() {
        let path = path();
        drop(Lifetime::install(&path, model()).unwrap());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "c71_lifetime::tests::c71_b12_crash_child", "--test-threads=1"])
            .env("C71_B12_CRASH_PATH", &path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(17));
        let mut store = Lifetime::open(&path, model()).unwrap();
        assert_eq!(store.counters(), (1, 1));
        assert_eq!(store.accepted_head(), [0; 32]);
        let pool = fixture(&mut store, 3);
        assert_eq!(pool.store.counters(), (2, 1));
        drop(pool);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_real_roles_reach_native_mac_after_durable_burn() {
        use volta_field::{Fp, Fp3};
        use volta_mac::c7_fp3::{
            c7_fp3_transfer_prover, c7_fp3_transfer_verifier, C7Fp3ProverAuthed,
            C7Fp3TransferCorrection, C7Fp3VerifierKey,
        };
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let target = field([17, 19, 23]); // diagnostic target, no PCS or W claim
        let ppath = path();
        let vpath = path();
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        pc.set_read_timeout(Some(std::time::Duration::from_secs(20))).unwrap();
        vc.set_read_timeout(Some(std::time::Duration::from_secs(20))).unwrap();
        let prover_path = ppath.clone();
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, model()).unwrap();
            let mut pool = store.prover(&mut pc, [4; 32], [5; 32], 3).unwrap();
            pool.attempt(1, |a, rows, _| {
                assert_eq!(a.ordinal, 1);
                let x = field([rows[0][0], rows[1][0], rows[2][0]]);
                let tag = |r: [u64; 4]| field([r[1], r[2], r[3]]);
                let t = tag(rows[0]) + u * tag(rows[1]) + u * u * tag(rows[2]);
                let (correction, authed) =
                    c7_fp3_transfer_prover(C7Fp3ProverAuthed::new(x, t), target);
                pc.write_all(&correction.to_bytes())?;
                pc.write_all(&authed.m.to_bytes())?;
                Ok(((), None))
            })
            .unwrap();
        });
        {
            let mut store = Lifetime::install(&vpath, model()).unwrap();
            let mut pool = store.verifier(&mut vc, [4; 32], [5; 32], 3).unwrap();
            pool.attempt(1, |a, rows, delta| {
                assert_eq!(a.ordinal, 1);
                let native_delta = Fp3::ZERO - field(*delta.unwrap());
                let k = field(rows[0]) + u * field(rows[1]) + u * u * field(rows[2]);
                let mut bytes = [0; 24];
                vc.read_exact(&mut bytes)?;
                let correction = C7Fp3TransferCorrection::from_bytes(&bytes).unwrap();
                let key =
                    c7_fp3_transfer_verifier(C7Fp3VerifierKey::new(k), native_delta, correction);
                vc.read_exact(&mut bytes)?;
                let tag = Fp3::from_bytes(&bytes).unwrap();
                assert_eq!(key.k, tag + native_delta * target);
                for basis in [Fp3::ONE, u, u * u] {
                    assert_ne!(key.k, tag + native_delta * (target + basis));
                }
                Ok(((), None))
            })
            .unwrap();
        }
        prover.join().unwrap();
        for path in [ppath, vpath] {
            let store = Lifetime::open(&path, model()).unwrap();
            assert_eq!(store.counters(), (1, 1));
            assert_eq!(store.accepted_head(), [0; 32]);
            drop(store);
            std::fs::remove_file(path).unwrap();
        }
    }
}

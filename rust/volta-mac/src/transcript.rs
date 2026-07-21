//! Transcript accounting and verifier challenge derivation.
//!
//! Every protocol message is charged to a labelled byte ledger (the P2 gate
//! compares totals against the analytic budget). Challenges are drawn from a
//! verifier-side ChaCha stream — this mocks the *interactive* DV exchange
//! (declared shortcut: in the deployed protocol challenges come fresh from V
//! after each prover message; they are NOT Fiat–Shamir hashes and must not be
//! derivable by the prover from public data alone).

use std::collections::BTreeMap;
use volta_field::{Fp2, FpStream};

pub struct Transcript {
    challenges: FpStream,
    bytes: BTreeMap<&'static str, u64>,
    n_messages: u64,
}

impl Transcript {
    /// `seed` is the verifier's challenge seed (independent of the PCG seed).
    pub fn new(seed: [u8; 32]) -> Transcript {
        Transcript {
            challenges: FpStream::domain_separated(seed, u64::MAX),
            bytes: BTreeMap::new(),
            n_messages: 0,
        }
    }

    /// Charge `n` bytes of prover→verifier message under `label`.
    pub fn append(&mut self, label: &'static str, n: u64) {
        *self.bytes.entry(label).or_insert(0) += n;
        self.n_messages += 1;
    }

    /// Fresh verifier challenge in `E` (only sound after the prover's
    /// corresponding message has been appended — callers keep that order).
    pub fn challenge_fp2(&mut self) -> Fp2 {
        self.challenges.next_fp2()
    }

    /// Fresh exact-bit verifier challenge for a power-of-two query domain.
    pub fn challenge_bits(&mut self, width: u8) -> u64 {
        self.challenges.next_bits(width)
    }

    pub fn bytes_for(&self, label: &str) -> u64 {
        self.bytes.get(label).copied().unwrap_or(0)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.values().sum()
    }

    pub fn ledger(&self) -> &BTreeMap<&'static str, u64> {
        &self.bytes
    }
}

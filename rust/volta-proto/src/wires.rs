//! Wire-claim ledger for the P4 fused blocks: internal wires are NOT
//! authenticated element-wise; consumers (GEMM sumchecks, hadamard, linear
//! relations) end with MLE evaluation claims on them, accumulated here and
//! drained by the wire's owner instance (the LogUp instance that proves the
//! wire, via aux-claim folding into its leaf-layer sumcheck) or by a
//! boundary MAC opening / PCS opening at the chain ends.
//!
//! Structural check: a proof is complete only when every wire's claims have
//! been drained — `finish()` panics otherwise (prover-side bug, not an
//! attack path; the verifier's checks fail independently).

use volta_field::Fp2;
use volta_mac::{ProverAuthed, VerifierKey};
use std::collections::BTreeMap;

/// Wire identity: (layer, name). Names are the witness field names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireId {
    pub layer: u8,
    pub name: &'static str,
}

pub struct WireClaimP {
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
}

pub struct WireClaimV {
    pub point: Vec<Fp2>,
    pub key: VerifierKey,
}

#[derive(Default)]
pub struct ClaimLedger {
    claims: BTreeMap<WireId, Vec<WireClaimP>>,
}

impl ClaimLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, wire: WireId, point: Vec<Fp2>, value: ProverAuthed) {
        self.claims.entry(wire).or_default().push(WireClaimP { point, value });
    }

    /// Take all pending claims on `wire` (the owner instance folds them).
    pub fn drain(&mut self, wire: WireId) -> Vec<WireClaimP> {
        self.claims.remove(&wire).unwrap_or_default()
    }

    pub fn pending(&self, wire: WireId) -> usize {
        self.claims.get(&wire).map_or(0, |v| v.len())
    }

    /// End-of-proof structural check.
    pub fn finish(self) {
        if let Some((w, v)) = self.claims.iter().find(|(_, v)| !v.is_empty()) {
            panic!("undrained wire claims: {:?} has {} pending", w, v.len());
        }
    }
}

/// Verifier mirror (same drain discipline, key side).
#[derive(Default)]
pub struct KeyLedger {
    claims: BTreeMap<WireId, Vec<WireClaimV>>,
}

impl KeyLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, wire: WireId, point: Vec<Fp2>, key: VerifierKey) {
        self.claims.entry(wire).or_default().push(WireClaimV { point, key });
    }
    pub fn drain(&mut self, wire: WireId) -> Vec<WireClaimV> {
        self.claims.remove(&wire).unwrap_or_default()
    }
    pub fn finish(self) -> bool {
        self.claims.values().all(|v| v.is_empty())
    }
}

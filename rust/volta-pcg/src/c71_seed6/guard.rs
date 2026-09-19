//! Reduced guard consumer over the original Seed6 MACs. The caller must bind
//! the returned public prefix into its one-shot challenge transcript. This
//! component does not implement the outer FS, seal, cGGM or F_EQ lifecycle.
use super::real::{RealProverOutput, RealVerifierOutput};
use volta_field::{Fp, Fp3, P};
use volta_mac::c7_fp3::{
    c7_fp3_product_batch_prover, c7_fp3_product_batch_verify, C7Fp3ProverAuthed as Auth,
    C7Fp3VerifierKey as Key,
};
use zeroize::Zeroize;

const BASIS: [Fp3; 3] =
    [Fp3::ONE, Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO), Fp3::new(Fp::ZERO, Fp::ZERO, Fp::ONE)];
const DOMAIN: &[u8] = b"VOLTA-C71-Seed6-path-guard-v1";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Shape,
    Noncanonical,
    Rejected,
}

struct Frozen {
    blocks: usize,
    height: usize,
    corrections: Vec<u64>,
    prefix: [u8; 32],
}
impl Frozen {
    fn new(
        binding: [u8; 32],
        rows: usize,
        blocks: usize,
        height: usize,
        corrections: Vec<u64>,
    ) -> Result<Self, Error> {
        if binding == [0; 32]
            || blocks == 0
            || blocks > 675
            || height == 0
            || height > 19
            || rows < blocks * (height + 4) + 3
            || corrections.len() != blocks * (height + 1)
        {
            return Err(Error::Shape);
        }
        if corrections.iter().any(|&x| x >= P) {
            return Err(Error::Noncanonical);
        }
        let mut hash = blake3::Hasher::new();
        hash.update(DOMAIN);
        hash.update(&binding);
        for n in [rows, blocks, height] {
            hash.update(&(n as u64).to_le_bytes());
        }
        // IDs are implicit in the fixed recipe, never received from a peer.
        // Mask/split rows are disjoint from beta/path rows by construction.
        for (i, &correction) in corrections.iter().enumerate() {
            let row = (i / (height + 1)) * (height + 4) + i % (height + 1);
            hash.update(&(row as u64).to_le_bytes());
            hash.update(&correction.to_le_bytes());
        }
        Ok(Self { blocks, height, corrections, prefix: *hash.finalize().as_bytes() })
    }
    fn mask_start(&self) -> usize {
        self.blocks * (self.height + 4)
    }
    fn triple_rows(&self, index: usize) -> (usize, usize, usize) {
        let block = index / self.height;
        let beta = block * (self.height + 4);
        (beta, beta + 1 + index % self.height, block * (self.height + 1))
    }
}

pub(super) struct ProverGuard {
    seed: RealProverOutput,
    frozen: Frozen,
}
pub(super) struct VerifierGuard {
    seed: RealVerifierOutput,
    frozen: Frozen,
}
pub(super) struct VerifierChallenged {
    seed: RealVerifierOutput,
    frozen: Frozen,
    lambda: Fp3,
}
// No Clone, public constructor or access to pre-guard verifier seed. A future
// c producer must consume this capability; no c producer exists here yet.
pub(super) struct GuardAccepted {
    seed: RealVerifierOutput,
    frozen: Frozen,
}
pub(super) struct ProverFinished {
    seed: RealProverOutput,
    frozen: Frozen,
}

fn auth(seed: &RealProverOutput, row: usize) -> Auth {
    Auth::new(Fp3::from_base(Fp::new(seed.values[row])), seed.tags[row].fp3())
}
fn pack_auth(seed: &RealProverOutput, start: usize) -> Auth {
    (0..3).fold(Auth::ZERO, |sum, j| sum.add(auth(seed, start + j).scale(BASIS[j])))
}
fn pack_key(seed: &RealVerifierOutput, start: usize) -> Key {
    Key::new((0..3).fold(Fp3::ZERO, |sum, j| sum + BASIS[j] * seed.keys[start + j].fp3()))
}

impl ProverGuard {
    pub(super) fn freeze(
        seed: RealProverOutput,
        blocks: usize,
        height: usize,
        corrections: Vec<u64>,
    ) -> Result<Self, Error> {
        if seed.values.len() != seed.tags.len() {
            return Err(Error::Shape);
        }
        let frozen = Frozen::new(seed.binding, seed.values.len(), blocks, height, corrections)?;
        Ok(Self { seed, frozen })
    }
    // Callback runs only after the ordered corrections/IDs are immutable.
    // It is a caller obligation to use the same reserved global FS once.
    pub(super) fn prove(
        mut self,
        challenge: impl FnOnce([u8; 32]) -> Fp3,
    ) -> ([u8; 48], ProverFinished) {
        let lambda = challenge(self.frozen.prefix);
        let triples = (0..self.frozen.blocks * self.frozen.height).map(|i| {
            let (beta, row, offset) = self.frozen.triple_rows(i);
            let b = auth(&self.seed, beta);
            let beta_x = b.x + Fp3::from_base(Fp::new(self.frozen.corrections[offset]));
            let g = auth(&self.seed, row);
            let gamma = g.x
                - Fp3::from_base(Fp::new(
                    self.frozen.corrections[offset + 1 + i % self.frozen.height],
                ));
            [Auth::new(gamma, g.m), Auth::new(gamma - beta_x, g.m - b.m), Auth::ZERO]
        });
        let start = self.frozen.mask_start();
        let proof = c7_fp3_product_batch_prover(triples, pack_auth(&self.seed, start), lambda);
        for row in start..start + 3 {
            self.seed.values[row].zeroize();
            self.seed.tags[row].zeroize();
        }
        let mut wire = [0; 48];
        wire[..24].copy_from_slice(&proof[0].to_bytes());
        wire[24..].copy_from_slice(&proof[1].to_bytes());
        (wire, ProverFinished { seed: self.seed, frozen: self.frozen })
    }
}
impl VerifierGuard {
    pub(super) fn freeze(
        seed: RealVerifierOutput,
        blocks: usize,
        height: usize,
        corrections: Vec<u64>,
    ) -> Result<Self, Error> {
        let frozen = Frozen::new(seed.binding, seed.keys.len(), blocks, height, corrections)?;
        Ok(Self { seed, frozen })
    }
    // Call before receiving the guard proof. No proof argument or getter is
    // available while this capability fixes the challenge.
    pub(super) fn challenge(self, draw: impl FnOnce([u8; 32]) -> Fp3) -> VerifierChallenged {
        let lambda = draw(self.frozen.prefix);
        VerifierChallenged { seed: self.seed, frozen: self.frozen, lambda }
    }
}
impl VerifierChallenged {
    pub(super) fn verify(mut self, wire: &[u8]) -> Result<GuardAccepted, Error> {
        if wire.len() != 48 {
            return Err(Error::Shape);
        }
        let proof = [
            Fp3::from_bytes(&wire[..24]).map_err(|_| Error::Noncanonical)?,
            Fp3::from_bytes(&wire[24..]).map_err(|_| Error::Noncanonical)?,
        ];
        let lambda = self.lambda;
        // Same sign adaptation as the existing original-endpoint native pool:
        // bootstrap m=k+Delta*x becomes native k=m+(-Delta)*x.
        let delta = Fp3::ZERO - self.seed.delta.fp3();
        let triples = (0..self.frozen.blocks * self.frozen.height).map(|i| {
            let (beta, row, offset) = self.frozen.triple_rows(i);
            let beta_k = self.seed.keys[beta].fp3()
                + delta.mul_base(Fp::new(self.frozen.corrections[offset]));
            let gamma_k = self.seed.keys[row].fp3()
                - delta.mul_base(Fp::new(
                    self.frozen.corrections[offset + 1 + i % self.frozen.height],
                ));
            [Key::new(gamma_k), Key::new(gamma_k - beta_k), Key::ZERO]
        });
        let start = self.frozen.mask_start();
        if !c7_fp3_product_batch_verify(triples, pack_key(&self.seed, start), proof, lambda, delta)
        {
            return Err(Error::Rejected); // owned secret arrays erase on drop
        }
        for row in start..start + 3 {
            self.seed.keys[row].zeroize();
        }
        Ok(GuardAccepted { seed: self.seed, frozen: self.frozen })
    }
}

// Corrections retain the source's d=s-gamma convention; beta correction is
// target minus original. Honest nonzero-beta sampling is an outer obligation.
pub(super) fn corrections(
    seed: &RealProverOutput,
    height: usize,
    betas: &[u64],
    paths: &[u64],
) -> Result<Vec<u64>, Error> {
    if height == 0
        || height > 19
        || betas.is_empty()
        || betas.len() > 675
        || betas.len() != paths.len()
        || seed.values.len() < betas.len() * (height + 4) + 3
        || betas.iter().any(|&b| b >= P)
        || paths.iter().any(|&x| x >= 1 << height)
    {
        return Err(Error::Shape);
    }
    let mut out = Vec::with_capacity(betas.len() * (height + 1));
    for (block, (&beta, &path)) in betas.iter().zip(paths).enumerate() {
        let row = block * (height + 4);
        out.push((Fp::new(beta) - Fp::new(seed.values[row])).value());
        for level in 0..height {
            let bit = (path >> (height - 1 - level)) & 1;
            out.push(
                (Fp::new(seed.values[row + 1 + level]) - Fp::new(beta) * Fp::new(bit)).value(),
            );
        }
    }
    Ok(out)
}

/// Reduced integration check: the callback is a deterministic test coin,
/// not an implementation of the composed global bootstrap transcript.
pub(super) fn check_real_seed(prover: RealProverOutput, verifier: RealVerifierOutput) {
    let d = corrections(&prover, 2, &[17], &[2]).unwrap();
    let p = ProverGuard::freeze(prover, 1, 2, d.clone()).unwrap();
    let v = VerifierGuard::freeze(verifier, 1, 2, d).unwrap();
    assert_eq!(p.frozen.prefix, v.frozen.prefix);
    let lambda = Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5));
    let verifier = v.challenge(|_| lambda);
    let (proof, finished) = p.prove(|_| lambda);
    let accepted = verifier.verify(&proof).unwrap();
    check_remaining(finished, accepted);
}
fn check_remaining(p: ProverFinished, v: GuardAccepted) {
    let start = p.frozen.mask_start();
    assert_eq!(start, v.frozen.mask_start());
    assert_eq!(p.frozen.corrections, v.frozen.corrections);
    for row in 0..p.seed.values.len() {
        if (start..start + 3).contains(&row) {
            assert_eq!(p.seed.values[row], 0);
            assert_eq!(p.seed.tags[row].fp3(), Fp3::ZERO);
            assert_eq!(v.seed.keys[row].fp3(), Fp3::ZERO);
        } else {
            assert_eq!(
                p.seed.tags[row].fp3(),
                v.seed.keys[row].fp3() + v.seed.delta.fp3().mul_base(Fp::new(p.seed.values[row]))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{real::NamedCapacities, Fp3Words, Seed6Work};
    use super::*;
    use crate::c71_bootstrap::Audit;
    use zeroize::Zeroizing;
    fn fixture() -> (RealProverOutput, RealVerifierOutput) {
        let n = 15; // two h=2 blocks, three guard masks; split rows untouched
        let delta = Fp3::new(Fp::new(11), Fp::new(13), Fp::new(17));
        let values: Vec<_> = (1..=n as u64).collect();
        let keys: Vec<_> = (0..n)
            .map(|i| Fp3Words::from_fp3(Fp3::new(Fp::new(31 + i as u64), Fp::new(41), Fp::new(43))))
            .collect();
        let tags: Vec<_> = values
            .iter()
            .zip(&keys)
            .map(|(&x, k)| Fp3Words::from_fp3(k.fp3() + delta.mul_base(Fp::new(x))))
            .collect();
        (
            RealProverOutput {
                binding: [9; 32],
                values: Zeroizing::new(values),
                tags: Zeroizing::new(tags),
                audit: Audit::default(),
                seed6_work: Seed6Work::for_rows(n),
                capacities: NamedCapacities::default(),
            },
            RealVerifierOutput {
                binding: [9; 32],
                delta: Zeroizing::new(Fp3Words::from_fp3(delta)),
                keys: Zeroizing::new(keys),
                audit: Audit::default(),
                seed6_work: Seed6Work::for_rows(n),
                capacities: NamedCapacities::default(),
            },
        )
    }
    fn lambda(_: [u8; 32]) -> Fp3 {
        Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5))
    }
    #[test]
    fn original_seed_guard_binary_zero_and_malformed_paths() {
        for fault in 0..7 {
            let (p, v) = fixture();
            // Both nonzero and maliciously chosen zero payload branches.
            let mut d = corrections(&p, 2, &[17, 0], &[2, 1]).unwrap();
            if fault == 1 {
                // nonbinary gamma=2*beta in the first block
                d[1] = (Fp::new(p.values[1]) - Fp::new(34)).value();
            }
            if fault == 2 {
                // beta=0, last gamma=1: prior Delta-recovery attack
                d[5] = (Fp::new(p.values[8]) - Fp::ONE).value();
            }
            let prover = ProverGuard::freeze(p, 2, 2, d.clone()).unwrap();
            if fault == 3 {
                d.swap(1, 2);
            }
            let verifier = VerifierGuard::freeze(v, 2, 2, d).unwrap();
            if fault == 3 {
                assert_ne!(prover.frozen.prefix, verifier.frozen.prefix);
            }
            let verifier = verifier.challenge(lambda);
            let (mut wire, finished) = prover.prove(lambda);
            if fault == 4 {
                wire[24] ^= 1;
            }
            if fault == 5 {
                wire[..8].copy_from_slice(&P.to_le_bytes());
            }
            let wire = if fault == 6 { &wire[..47] } else { &wire[..] };
            let result = verifier.verify(wire);
            if fault == 0 {
                check_remaining(finished, result.unwrap());
            } else {
                assert!(result.is_err(), "fault {fault}");
            }
        }
    }
    #[test]
    fn guard_recipe_shapes_ids_and_prefix_bindings() {
        let (p, v) = fixture();
        let d = corrections(&p, 2, &[17, 0], &[2, 1]).unwrap();
        assert!(Frozen::new([9; 32], 15, 2, 2, d[..5].to_vec()).is_err());
        assert!(Frozen::new([9; 32], 14, 2, 2, d.clone()).is_err());
        let mut invalid = d.clone();
        invalid[0] = P;
        assert!(Frozen::new([9; 32], 15, 2, 2, invalid).is_err());
        let frozen = Frozen::new([9; 32], 15, 2, 2, d.clone()).unwrap();
        assert_ne!(frozen.prefix, Frozen::new([8; 32], 15, 2, 2, d).unwrap().prefix);
        assert_eq!(
            (0..4).map(|i| frozen.triple_rows(i)).collect::<Vec<_>>(),
            vec![(0, 1, 0), (0, 2, 0), (6, 7, 3), (6, 8, 3)]
        );
        assert_eq!(frozen.mask_start(), 12);
        assert!(corrections(&p, 2, &[17], &[4]).is_err());
        drop(v);
        let canonical = Frozen::new([9; 32], 17553, 675, 19, vec![0; 13500]).unwrap();
        assert_eq!(canonical.corrections.capacity() * 8, 108000);
        assert_eq!(canonical.mask_start(), 15525);
        println!(
            "seed6_guard_workspace {}",
            serde_json::json!({
                "correction_heap_capacity":canonical.corrections.capacity()*8,
                "Frozen_size":core::mem::size_of::<Frozen>(),
                "ProverGuard_size":core::mem::size_of::<ProverGuard>(),
                "VerifierGuard_size":core::mem::size_of::<VerifierGuard>(),
                "VerifierChallenged_size":core::mem::size_of::<VerifierChallenged>(),
                "BLAKE3_Hasher_size":core::mem::size_of::<blake3::Hasher>(),
                "complete_stack_or_allocator_peak":false
            })
        );
    }
}

//! Reduced two-key F_EQ consumer. Both seeds must already be complete. This
//! module consumes their reserved tail once; the outer seal/burn, F_Rand and
//! guard/cGGM -> equality transition remain caller obligations, not credit here.
use super::real::{RealProverOutput, RealVerifierOutput};
use super::Fp3Words;
use rand::{CryptoRng, RngCore};
use volta_field::{Fp, Fp3};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"VOLTA-C71-Seed6-equality-v1";
const BASIS: [Fp3; 3] =
    [Fp3::ONE, Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO), Fp3::new(Fp::ZERO, Fp::ZERO, Fp::ONE)];

struct Prepared {
    role: u8,
    sid: [u8; 32],
    sender: RealProverOutput,
    receiver: RealVerifierOutput,
    values: Zeroizing<Vec<Fp3Words>>,
    corrections: Vec<u8>,
}
struct Frozen {
    local: Prepared,
    peer: Vec<Fp3Words>,
    prefix: [u8; 32],
}
struct Committed {
    role: u8,
    prefix: [u8; 32],
    commitment: [u8; 32],
    opening: Zeroizing<[u8; 56]>,
}
struct Openable {
    local: Committed,
    peer_commitment: [u8; 32],
}
fn pack_base(seed: &RealProverOutput, i: usize) -> Fp3 {
    (0..3).fold(Fp3::ZERO, |s, j| s + BASIS[j].mul_base(Fp::new(seed.values[i + j])))
}
fn pack_tags(seed: &RealProverOutput, i: usize) -> Fp3 {
    (0..3).fold(Fp3::ZERO, |s, j| s + BASIS[j] * seed.tags[i + j].fp3())
}
fn pack_keys(seed: &RealVerifierOutput, i: usize) -> Fp3 {
    (0..3).fold(Fp3::ZERO, |s, j| s + BASIS[j] * seed.keys[i + j].fp3())
}
fn commitment(prefix: &[u8; 32], role: u8, opening: &[u8; 56]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(b"/share/");
    h.update(prefix);
    h.update(&[role]);
    h.update(opening);
    *h.finalize().as_bytes()
}
impl Prepared {
    fn heap_bytes(&self) -> usize {
        self.sender.values.capacity() * 8
            + self.sender.tags.capacity() * 24
            + self.receiver.keys.capacity() * 24
            + self.values.capacity() * 24
            + self.corrections.capacity()
    }
    fn new(
        role: u8,
        sid: [u8; 32],
        mut sender: RealProverOutput,
        mut receiver: RealVerifierOutput,
        values: Zeroizing<Vec<Fp3Words>>,
    ) -> Result<Self, &'static str> {
        if role > 1
            || sid == [0; 32]
            || values.is_empty()
            || values.len() > 675
            || values.capacity() != values.len()
            || sender.binding == [0; 32]
            || receiver.binding == [0; 32]
            || sender.binding == receiver.binding
            || sender.values.len() != sender.tags.len()
            || sender.values.capacity() > sender.values.len() + 6
            || sender.tags.capacity() != sender.tags.len()
            || receiver.keys.capacity() != receiver.keys.len()
            || sender.values.len() != 3 * values.len()
            || receiver.keys.len() != 3 * values.len()
        {
            return Err("equality seed/input shape");
        }
        // Setup diagnostics have no equality consumer; release their Vec bodies.
        sender.audit = crate::c71_bootstrap::Audit::default();
        receiver.audit = crate::c71_bootstrap::Audit::default();
        // This consumer accepts only an exact reserved tail. Prefix ownership
        // cannot enter F_EQ or be recovered from the consumed output.
        let mut corrections = Vec::with_capacity(24 * values.len());
        for (i, x) in values.iter().enumerate() {
            corrections.extend_from_slice(&(x.fp3() - pack_base(&sender, 3 * i)).to_bytes());
        }
        Ok(Self { role, sid, sender, receiver, values, corrections })
    }
    fn freeze(self, peer: Vec<u8>) -> Result<Frozen, &'static str> {
        if peer.len() != self.corrections.len() || peer.capacity() != peer.len() {
            return Err("equality correction length");
        }
        let mut peer_values = Vec::with_capacity(self.values.len());
        for bytes in peer.chunks_exact(24) {
            peer_values.push(Fp3Words::from_fp3(
                Fp3::from_bytes(bytes).map_err(|_| "equality noncanonical correction")?,
            ));
        }
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(b"/corrections/");
        h.update(&self.sid);
        h.update(&(self.values.len() as u64).to_le_bytes());
        // Role 0 owns key0 and value1; role 1 owns value0 and key1.
        let seeds = if self.role == 0 {
            [self.receiver.binding, self.sender.binding]
        } else {
            [self.sender.binding, self.receiver.binding]
        };
        for seed in seeds {
            h.update(&seed);
        }
        for role in 0..2 {
            h.update(&[role]);
            h.update(if role == self.role { &self.corrections } else { &peer });
        }
        Ok(Frozen { local: self, peer: peer_values, prefix: *h.finalize().as_bytes() })
    }
}
impl Frozen {
    // Called after both correction frames are immutable. Production must supply
    // the same fresh F_Rand coefficients, not the deterministic test callback.
    fn commit(
        self,
        draw: impl FnOnce([u8; 32], usize) -> Vec<Fp3>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Committed, &'static str> {
        let n = self.local.values.len();
        let coefficients = draw(self.prefix, n);
        if coefficients.len() != n || coefficients.capacity() != n {
            return Err("equality coin count");
        }
        let delta = self.local.receiver.delta.fp3();
        let (mut value, mut tag, mut key) = (Fp3::ZERO, Fp3::ZERO, Fp3::ZERO);
        for (i, &r) in coefficients.iter().enumerate() {
            value += r * self.local.values[i].fp3();
            tag += r * pack_tags(&self.local.sender, 3 * i);
            key += r * (pack_keys(&self.local.receiver, 3 * i) - delta * self.peer[i].fp3());
        }
        let share = if self.local.role == 0 {
            -key - delta * value - tag
        } else {
            tag + delta * value + key
        };
        let mut opening = Zeroizing::new([0; 56]);
        opening[..24].copy_from_slice(&share.to_bytes());
        rng.fill_bytes(&mut opening[24..]);
        let commitment = commitment(&self.prefix, self.local.role, &opening);
        Ok(Committed { role: self.local.role, prefix: self.prefix, commitment, opening })
        // Both owned seeds and inputs are erased on drop after share computation.
    }
}
impl Committed {
    fn accept_peer_commitment(self, peer_commitment: [u8; 32]) -> Openable {
        Openable { local: self, peer_commitment }
    }
}
impl Openable {
    fn opening(&self) -> [u8; 56] {
        *self.local.opening
    }
    fn verify(self, peer: &[u8]) -> Result<(), &'static str> {
        let bytes: &[u8; 56] = peer.try_into().map_err(|_| "equality opening length")?;
        let share = Fp3::from_bytes(&bytes[..24]).map_err(|_| "equality noncanonical share")?;
        if commitment(&self.local.prefix, 1 - self.local.role, bytes) != self.peer_commitment {
            return Err("equality share commitment");
        }
        let local = Fp3::from_bytes(&self.local.opening[..24]).unwrap();
        if local + share != Fp3::ZERO {
            return Err("equality mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        real::{self, NamedCapacities},
        Seed6Work,
    };
    use super::*;
    use crate::c71_bootstrap::{Audit, Context};
    use rand::{rngs::StdRng, SeedableRng};
    fn ideal(n: usize, id: u8) -> (RealProverOutput, RealVerifierOutput) {
        let delta = Fp3::new(Fp::new(id as u64 + 11), Fp::new(13), Fp::new(17));
        let values: Vec<_> = (0..n as u64).map(|i| i + 5 + id as u64).collect();
        let keys: Vec<_> = (0..n as u64)
            .map(|i| Fp3Words::from_fp3(Fp3::new(Fp::new(i + 31), Fp::new(41), Fp::new(43))))
            .collect();
        let tags = values
            .iter()
            .zip(&keys)
            .map(|(&x, k)| Fp3Words::from_fp3(k.fp3() + delta.mul_base(Fp::new(x))))
            .collect();
        (
            RealProverOutput {
                binding: [id; 32],
                values: Zeroizing::new(values),
                tags: Zeroizing::new(tags),
                audit: Audit::default(),
                seed6_work: Seed6Work::for_rows(n),
                capacities: NamedCapacities::default(),
            },
            RealVerifierOutput {
                binding: [id; 32],
                delta: Zeroizing::new(Fp3Words::from_fp3(delta)),
                keys: Zeroizing::new(keys),
                audit: Audit::default(),
                seed6_work: Seed6Work::for_rows(n),
                capacities: NamedCapacities::default(),
            },
        )
    }
    fn inputs(x: &[Fp3]) -> Zeroizing<Vec<Fp3Words>> {
        Zeroizing::new(x.iter().map(|&v| Fp3Words::from_fp3(v)).collect())
    }
    fn coins(_: [u8; 32], n: usize) -> Vec<Fp3> {
        (0..n).map(|i| Fp3::new(Fp::new(i as u64 + 2), Fp::new(3), Fp::new(5))).collect()
    }
    fn commit_pair(p0: Prepared, p1: Prepared) -> (Committed, Committed) {
        let c0 = p0.corrections.clone();
        let c1 = p1.corrections.clone();
        let f0 = p0.freeze(c1).unwrap();
        let f1 = p1.freeze(c0).unwrap();
        assert_eq!(f0.prefix, f1.prefix);
        for f in [&f0, &f1] {
            assert_eq!(f.peer.capacity(), f.local.values.len());
            assert_eq!(f.local.corrections.capacity(), 24 * f.local.values.len());
            assert_eq!(f.local.sender.audit.sent_frames.capacity(), 0);
            assert_eq!(f.local.receiver.audit.phase_seconds.capacity(), 0);
            println!(
                "seed6_equality_heap {}",
                serde_json::json!({
                "role":f.local.role, "n":f.local.values.len(),
                "sender_rows":f.local.sender.values.len(),
                "sender_values_capacity":f.local.sender.values.capacity(),
                "receiver_rows":f.local.receiver.keys.len(),
                "prepare_owned_heap":f.local.heap_bytes(),
                "freeze_or_commit_owned_heap":f.local.heap_bytes()+48*f.local.values.len(),
                "audit_heap_after_prepare":0,"complete_physical_peak":false})
            );
        }

        (
            f0.commit(coins, &mut StdRng::seed_from_u64(70)).unwrap(),
            f1.commit(coins, &mut StdRng::seed_from_u64(71)).unwrap(),
        )
    }
    fn prepared_pair(x: &[Fp3], y: &[Fp3]) -> (Prepared, Prepared) {
        let (p0, v0) = ideal(3 * x.len(), 1);
        let (p1, v1) = ideal(3 * x.len(), 2);
        (
            Prepared::new(0, [8; 32], p1, v0, inputs(x)).unwrap(),
            Prepared::new(1, [8; 32], p0, v1, inputs(y)).unwrap(),
        )
    }
    #[test]
    fn c71_seed6_tail_reservation_rejects_unsplit_prefix_and_bad_shapes() {
        let x = [Fp3::ONE];
        let (p, _) = ideal(12, 1);
        let (_, v) = ideal(3, 2);
        assert!(Prepared::new(0, [8; 32], p, v, inputs(&x)).is_err());
        for tail in [0, 12, 13] {
            let (p, v) = ideal(12, 1);
            assert!(real::reserve_equality_prover_tail(p, tail).is_err());
            assert!(real::reserve_equality_verifier_tail(v, tail).is_err());
        }
        let (mut p, _) = ideal(12, 1);
        p.tags.pop();
        assert!(real::reserve_equality_prover_tail(p, 3).is_err());
    }
    #[test]
    fn c71_seed6_equality_two_keys_match_and_reject_framing() {
        let x = [Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11)), Fp3::from_base(Fp::new(19))];
        for fault in 0..7 {
            let mut y = x;
            if fault == 1 {
                y[1] += Fp3::ONE;
            }
            let (p0, p1) = prepared_pair(&x, &y);
            let (c0, mut c1) = commit_pair(p0, p1);
            if fault == 5 {
                // A canonical but wrong share committed before the peer opens.
                let changed = Fp3::from_bytes(&c1.opening[..24]).unwrap() + Fp3::ONE;
                c1.opening[..24].copy_from_slice(&changed.to_bytes());
                c1.commitment = commitment(&c1.prefix, c1.role, &c1.opening);
            }
            let (h0, h1) = (c0.commitment, c1.commitment);
            let o0 = c0.accept_peer_commitment(if fault == 6 { h0 } else { h1 });
            let o1 = c1.accept_peer_commitment(h0);
            let b0 = o0.opening();
            let mut b1 = o1.opening().to_vec();
            if fault == 2 {
                b1[0] ^= 1;
            }
            if fault == 3 {
                b1.pop();
            }
            if fault == 4 {
                b1[..8].copy_from_slice(&volta_field::P.to_le_bytes());
            }
            assert_eq!(o0.verify(&b1).is_ok(), fault == 0);
            assert_eq!(o1.verify(&b0).is_ok(), fault != 1 && fault != 5);
        }
        let (p0, p1) = prepared_pair(&x, &x);
        let mut bad = p1.corrections.clone();
        bad[..8].copy_from_slice(&volta_field::P.to_le_bytes());
        assert!(p0.freeze(bad).is_err());
        let (p0, p1) = prepared_pair(&x, &x);
        assert!(p0.freeze(p1.corrections[..47].to_vec()).is_err());
        let (p0, p1) = prepared_pair(&x, &x);
        assert!(p0
            .freeze(p1.corrections)
            .unwrap()
            .commit(|_, _| vec![], &mut StdRng::seed_from_u64(1))
            .is_err());
        println!(
            "seed6_equality {}",
            serde_json::json!({
            "Prepared_bytes":std::mem::size_of::<Prepared>(),
            "Frozen_bytes":std::mem::size_of::<Frozen>(),
            "Committed_bytes":std::mem::size_of::<Committed>(),
            "Openable_bytes":std::mem::size_of::<Openable>(),
            "blake3_hasher_bytes":std::mem::size_of::<blake3::Hasher>(),
            "equal_share_sum_zero":true,"global_F_Rand_and_seal_credit":false})
        );
    }
    fn real_pair(n: usize, direction: u8) -> (RealProverOutput, RealVerifierOutput) {
        use std::{os::unix::net::UnixStream, thread, time::Duration};
        let (left, right) = UnixStream::pair().unwrap();
        for s in [&left, &right] {
            s.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let context =
            || Context { session: [0x31; 32], channel: [0x51; 32], capacity: [0x71; 32], rows: n };
        let c = context();
        let sender = thread::spawn(move || {
            real::prover_with_rng(
                left,
                c,
                direction,
                &mut StdRng::seed_from_u64(100 + direction as u64),
            )
            .unwrap()
        });
        let receiver = real::verifier_with_rng(
            right,
            context(),
            direction,
            &mut StdRng::seed_from_u64(200 + direction as u64),
        )
        .unwrap();
        (sender.join().unwrap(), receiver)
    }
    #[test]
    fn c71_seed6_equality_real_opposite_role_seeds() {
        let (p0, v0) = real_pair(3, 0);
        let (p1, v1) = real_pair(3, 1);
        let x = [Fp3::new(Fp::new(17), Fp::new(19), Fp::new(23))];
        let (c0, c1) = commit_pair(
            Prepared::new(0, [8; 32], p1, v0, inputs(&x)).unwrap(),
            Prepared::new(1, [8; 32], p0, v1, inputs(&x)).unwrap(),
        );
        let (h0, h1) = (c0.commitment, c1.commitment);
        let o0 = c0.accept_peer_commitment(h1);
        let o1 = c1.accept_peer_commitment(h0);
        let (b0, b1) = (o0.opening(), o1.opening());
        assert!(o0.verify(&b1).is_ok());
        assert!(o1.verify(&b0).is_ok());
    }

    #[test]
    fn c71_seed6_real_prefix_guard_and_exact_equality_tail_are_disjoint() {
        let (p0, v0) = real_pair(12, 0);
        let (p1, v1) = real_pair(12, 1);
        let p0 = real::reserve_equality_prover_tail(p0, 3).unwrap();
        let v0 = real::reserve_equality_verifier_tail(v0, 3).unwrap();
        let p1 = real::reserve_equality_prover_tail(p1, 3).unwrap();
        let v1 = real::reserve_equality_verifier_tail(v1, 3).unwrap();
        assert_eq!((p0.prefix.values.len(), p0.equality_tail.values.len()), (9, 3));
        assert_eq!((v0.prefix.keys.len(), v0.equality_tail.keys.len()), (9, 3));
        assert_eq!(p0.work.copied_payload_bytes, 3 * 32);
        assert_eq!(v0.work.copied_payload_bytes, 3 * 24);
        assert_eq!(p0.work.named_vec_capacity_peak_bytes, p0.work.destination_vec_capacity_bytes);
        assert_eq!(v0.work.named_vec_capacity_peak_bytes, v0.work.destination_vec_capacity_bytes);
        assert_eq!(
            p0.work.destination_vec_capacity_bytes,
            8 * (p0.prefix.values.capacity() + p0.equality_tail.values.capacity())
                + 24 * (p0.prefix.tags.capacity() + p0.equality_tail.tags.capacity())
        );
        assert_eq!(
            v0.work.destination_vec_capacity_bytes,
            24 * (v0.prefix.keys.capacity() + v0.equality_tail.keys.capacity())
        );
        assert_eq!(p0.prefix.binding, p0.equality_tail.binding);
        assert_eq!(v0.prefix.binding, v0.equality_tail.binding);
        println!(
            "seed6_tail_reservation {}",
            serde_json::json!({
            "rows":12,"tail_rows":3,"prover":p0.work,"verifier":v0.work})
        );
        super::super::guard::check_real_seed(p0.prefix, v0.prefix);
        super::super::guard::check_real_seed(p1.prefix, v1.prefix);
        let x = [Fp3::new(Fp::new(17), Fp::new(19), Fp::new(23))];
        let (c0, c1) = commit_pair(
            Prepared::new(0, [8; 32], p1.equality_tail, v0.equality_tail, inputs(&x)).unwrap(),
            Prepared::new(1, [8; 32], p0.equality_tail, v1.equality_tail, inputs(&x)).unwrap(),
        );
        let (h0, h1) = (c0.commitment, c1.commitment);
        let (o0, o1) = (c0.accept_peer_commitment(h1), c1.accept_peer_commitment(h0));
        let (b0, b1) = (o0.opening(), o1.opening());
        assert!(o0.verify(&b1).is_ok());
        assert!(o1.verify(&b0).is_ok());
    }
}

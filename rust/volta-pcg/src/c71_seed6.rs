//! Test-only native boundary for the selected C7.1 Fp6 seed candidate.
//!
//! This checks a complete K6 MAC relation with six independent mask rows and
//! only then samples the E-linear compression map into Fp3. It deliberately
//! has no production entry. The reduced real adapter binds a suite handshake,
//! 384 MR19 OTs and streamed AES-COPE. Outer one-use lifetime, guard and
//! opposite-role composition remain open.

mod real;

use p521::elliptic_curve::subtle::ConstantTimeEq;
use volta_field::{Fp, Fp3};
use zeroize::{Zeroize, Zeroizing};

const LIMBS: usize = 6;
const MASKS: usize = 6;

const MR19: crate::c71_bootstrap::Mr19Profile = crate::c71_bootstrap::Mr19Profile {
    ot_count: 384,
    group_receiver_domain: b"C71S6/MR19/group/receiver/v1/",
    seed_sender_domain: b"C71S6/MR19/seed/sender/v1/",
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct K6([u64; LIMBS]);

impl K6 {
    const ZERO: Self = Self([0; LIMBS]);

    fn new(c0: Fp3, c1: Fp3) -> Self {
        Self([
            c0.c0.value(),
            c0.c1.value(),
            c0.c2.value(),
            c1.c0.value(),
            c1.c1.value(),
            c1.c2.value(),
        ])
    }

    fn parts(self) -> [Fp3; 2] {
        [
            Fp3::new(Fp::new(self.0[0]), Fp::new(self.0[1]), Fp::new(self.0[2])),
            Fp3::new(Fp::new(self.0[3]), Fp::new(self.0[4]), Fp::new(self.0[5])),
        ]
    }

    fn basis(index: usize) -> Self {
        let mut limbs = [Fp::ZERO; LIMBS];
        limbs[index] = Fp::ONE;
        Self::from_limbs(limbs)
    }

    fn from_limbs(x: [Fp; LIMBS]) -> Self {
        Self(x.map(Fp::value))
    }

    fn add(self, rhs: Self) -> Self {
        Self(std::array::from_fn(|i| (Fp::new(self.0[i]) + Fp::new(rhs.0[i])).value()))
    }

    fn mul(self, rhs: Self) -> Self {
        // K6 = Fp3[v]/(v^2-7).
        let seven = Fp::new(7);
        let [a, b] = self.parts();
        let [c, d] = rhs.parts();
        Self::new(a * c + (b * d).mul_base(seven), a * d + b * c)
    }

    fn mul_base(self, rhs: Fp) -> Self {
        let [c0, c1] = self.parts();
        Self::new(c0.mul_base(rhs), c1.mul_base(rhs))
    }

    fn encode(self) -> [u8; 48] {
        let mut out = [0; 48];
        for (index, limb) in self.0.into_iter().enumerate() {
            out[8 * index..8 * (index + 1)].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Seed6Error> {
        if bytes.len() != 48 {
            return Err(Seed6Error::WrongLength);
        }
        let c0 = Fp3::from_bytes(&bytes[..24]).map_err(|error| match error {
            volta_field::Fp3DecodeError::WrongLength { .. } => Seed6Error::WrongLength,
            volta_field::Fp3DecodeError::NonCanonicalLimb { limb } => {
                Seed6Error::NonCanonicalLimb(limb)
            }
        })?;
        let c1 = Fp3::from_bytes(&bytes[24..]).map_err(|error| match error {
            volta_field::Fp3DecodeError::WrongLength { .. } => Seed6Error::WrongLength,
            volta_field::Fp3DecodeError::NonCanonicalLimb { limb } => {
                Seed6Error::NonCanonicalLimb(3 + limb)
            }
        })?;
        Ok(Self::new(c0, c1))
    }

    fn compress(self, alpha: [Fp3; 2]) -> Fp3 {
        let [c0, c1] = self.parts();
        alpha[0] * c0 + alpha[1] * c1
    }
}

impl Zeroize for K6 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Seed6Error {
    WrongLength,
    NonCanonicalLimb(usize),
    Shape,
    CorrelationCheck,
    ZeroCompressedKey,
}

struct ProverRows<'a> {
    values: &'a [Fp],
    tags: &'a [K6],
    mask_values: &'a [Fp; MASKS],
    mask_tags: &'a [K6; MASKS],
    challenges: &'a [K6],
}

struct VerifierRows<'a> {
    keys: &'a [K6],
    mask_keys: &'a [K6; MASKS],
    challenges: &'a [K6],
}

#[derive(Debug)]
struct ProverCheck {
    x: Zeroizing<K6>,
    z: Zeroizing<K6>,
}

#[derive(Debug)]
struct VerifierCheck(Zeroizing<K6>);

impl ProverCheck {
    fn new() -> Self {
        Self { x: Zeroizing::new(K6::ZERO), z: Zeroizing::new(K6::ZERO) }
    }
    fn absorb(&mut self, chi: K6, value: Fp, tag: K6) {
        *self.x = self.x.add(chi.mul_base(value));
        *self.z = self.z.add(chi.mul(tag));
    }
}
impl VerifierCheck {
    fn new() -> Self {
        Self(Zeroizing::new(K6::ZERO))
    }
    fn absorb(&mut self, chi: K6, key: K6) {
        *self.0 = self.0.add(chi.mul(key));
    }
}

struct Checked(());

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Fp3Words([u64; 3]);

impl Fp3Words {
    fn from_fp3(value: Fp3) -> Self {
        Self([value.c0.value(), value.c1.value(), value.c2.value()])
    }

    fn fp3(self) -> Fp3 {
        Fp3::new(Fp::new(self.0[0]), Fp::new(self.0[1]), Fp::new(self.0[2]))
    }
}

impl Zeroize for Fp3Words {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CompressedRows {
    delta: Zeroizing<Fp3Words>,
    tags: Zeroizing<Vec<Fp3Words>>,
    keys: Zeroizing<Vec<Fp3Words>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Seed6Work {
    prover_k6_products: usize,
    prover_k6_base_products: usize,
    prover_k6_adds: usize,
    verifier_k6_products: usize,
    verifier_k6_adds: usize,
    relation_k6_products: usize,
    relation_k6_adds: usize,
    compression_fp3_products: usize,
    compression_fp3_adds: usize,
    masks: usize,
}

impl Seed6Work {
    fn for_rows(n: usize) -> Self {
        Self {
            prover_k6_products: n + MASKS,
            prover_k6_base_products: n + MASKS,
            prover_k6_adds: 2 * (n + MASKS),
            verifier_k6_products: n + MASKS,
            verifier_k6_adds: n + MASKS,
            relation_k6_products: 1,
            relation_k6_adds: 1,
            compression_fp3_products: 4 * n + 2,
            compression_fp3_adds: 2 * n + 1,
            masks: MASKS,
        }
    }
}

fn buffer_report(output: &CompressedRows) -> Seed6Buffers {
    let word_bytes = core::mem::size_of::<Fp3Words>();
    Seed6Buffers {
        prover_borrowed_bytes: output.tags.len() * (8 + 48 + 48) + MASKS * (8 + 48),
        verifier_borrowed_bytes: output.keys.len() * (48 + 48) + MASKS * 48,
        prover_check_bytes: 2 * core::mem::size_of::<K6>(),
        verifier_check_bytes: core::mem::size_of::<K6>(),
        prover_output_len_bytes: output.tags.len() * word_bytes,
        prover_output_capacity_bytes: output.tags.capacity() * word_bytes,
        verifier_output_len_bytes: (1 + output.keys.len()) * word_bytes,
        verifier_output_capacity_bytes: word_bytes + output.keys.capacity() * word_bytes,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Seed6Buffers {
    /// Logical bytes in the borrowed values/tags/challenges/masks; no allocation.
    prover_borrowed_bytes: usize,
    /// Logical bytes in the borrowed keys/challenges/masks; no allocation.
    verifier_borrowed_bytes: usize,
    prover_check_bytes: usize,
    verifier_check_bytes: usize,
    prover_output_len_bytes: usize,
    prover_output_capacity_bytes: usize,
    verifier_output_len_bytes: usize,
    verifier_output_capacity_bytes: usize,
}

fn prover_accumulators(rows: ProverRows<'_>) -> Result<ProverCheck, Seed6Error> {
    let n = rows.values.len();
    if n == 0 || rows.tags.len() != n || rows.challenges.len() != n {
        return Err(Seed6Error::Shape);
    }
    let mut check = ProverCheck::new();
    for i in 0..n {
        check.absorb(rows.challenges[i], rows.values[i], rows.tags[i]);
    }
    for h in 0..MASKS {
        check.absorb(K6::basis(h), rows.mask_values[h], rows.mask_tags[h]);
    }
    Ok(check)
}

fn verifier_accumulator(rows: VerifierRows<'_>) -> Result<VerifierCheck, Seed6Error> {
    if rows.keys.is_empty() || rows.keys.len() != rows.challenges.len() {
        return Err(Seed6Error::Shape);
    }
    let mut check = VerifierCheck::new();
    for i in 0..rows.keys.len() {
        check.absorb(rows.challenges[i], rows.keys[i]);
    }
    for h in 0..MASKS {
        check.absorb(K6::basis(h), rows.mask_keys[h]);
    }
    Ok(check)
}

fn verify_relation(
    delta: K6,
    prover: &ProverCheck,
    verifier: &VerifierCheck,
) -> Result<Checked, Seed6Error> {
    if !bool::from(prover.z.0.ct_eq(&verifier.0.add(delta.mul(*prover.x)).0)) {
        return Err(Seed6Error::CorrelationCheck);
    }
    Ok(Checked(()))
}

fn compress_prover(tags: &[K6], alpha: [Fp3; 2]) -> Zeroizing<Vec<Fp3Words>> {
    Zeroizing::new(tags.iter().map(|value| Fp3Words::from_fp3(value.compress(alpha))).collect())
}

fn compress_verifier(
    _checked: &Checked,
    delta: K6,
    keys: &[K6],
    alpha: [Fp3; 2],
) -> Result<(Zeroizing<Fp3Words>, Zeroizing<Vec<Fp3Words>>), Seed6Error> {
    let compressed_delta = Zeroizing::new(Fp3Words::from_fp3(delta.compress(alpha)));
    if bool::from(compressed_delta.0.ct_eq(&[0; 3])) {
        return Err(Seed6Error::ZeroCompressedKey);
    }
    let compressed_keys = Zeroizing::new(
        keys.iter().map(|value| Fp3Words::from_fp3(value.compress(alpha))).collect(),
    );
    Ok((compressed_delta, compressed_keys))
}

/// Test-only seed boundary. `alpha_after_check` models the protocol ordering:
/// it is not invoked on malformed input or a failed full-K6 correlation check.
fn check_then_compress(
    prover_rows: ProverRows<'_>,
    verifier_rows: VerifierRows<'_>,
    delta: K6,
    alpha_after_check: impl FnOnce() -> [Fp3; 2],
) -> Result<CompressedRows, Seed6Error> {
    let tags = prover_rows.tags;
    let keys = verifier_rows.keys;
    let prover = prover_accumulators(prover_rows)?;
    let verifier = verifier_accumulator(verifier_rows)?;
    let checked = verify_relation(delta, &prover, &verifier)?;
    let alpha = alpha_after_check();
    let tags = compress_prover(tags, alpha);
    let (delta, keys) = compress_verifier(&checked, delta, keys, alpha)?;
    Ok(CompressedRows { delta, tags, keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use volta_field::P;

    #[test]
    fn seed6_real_384_ot_preserves_choices_and_censuses_frames() {
        use crate::c71_bootstrap::{mr19_receiver, mr19_sender, Audit};
        use rand::{rngs::StdRng, SeedableRng};
        use std::os::unix::net::UnixStream;
        let delta = k([0, 1, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555, 1 << 63, volta_field::P - 1]);
        let context = b"C71S6v01/test-only/main-seed/session-0";
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        for channel in [&sender, &receiver] {
            channel.set_read_timeout(Some(std::time::Duration::from_secs(45))).unwrap();
            channel.set_write_timeout(Some(std::time::Duration::from_secs(45))).unwrap();
        }
        let peer = std::thread::spawn(move || {
            let mut audit = Audit::default();
            let seeds = mr19_sender(
                &mut sender,
                context,
                MR19,
                &mut StdRng::seed_from_u64(0x6350),
                &mut audit,
            )
            .unwrap();
            (seeds, audit)
        });
        let mut audit = Audit::default();
        let choices = |i: usize| ((delta.0[i / 64] >> (i % 64)) & 1) as u8;
        let selected = mr19_receiver(
            &mut receiver,
            context,
            MR19,
            choices,
            &mut StdRng::seed_from_u64(0x6351),
            &mut audit,
        )
        .unwrap();
        let (pairs, sender_audit) = peer.join().unwrap();
        assert_eq!(selected.len(), 384);
        for i in 0..384 {
            assert_eq!(selected[i], pairs[i][choices(i) as usize]);
            assert_ne!(selected[i], pairs[i][1 - choices(i) as usize]);
        }
        assert_eq!(audit.sent_frames, vec![(3, 51_465)]);
        assert_eq!(sender_audit.sent_frames, vec![(4, 51_465), (5, 24_585)]);
        assert_eq!(audit.received_frames, sender_audit.sent_frames);
        assert_eq!(sender_audit.received_frames, audit.sent_frames);
        assert_eq!(sender_audit.work.fixed_scalar_mul, 768);
        assert_eq!(sender_audit.work.variable_scalar_mul, 768);
        assert_eq!(audit.work.fixed_scalar_mul, 768);
        assert_eq!(audit.work.variable_scalar_mul, 768);
        assert_eq!(audit.work.group_hash, 768);
        assert_eq!(sender_audit.work.group_hash, 768);
        assert_eq!(audit.work.kdf, 768);
        assert_eq!(sender_audit.work.kdf, 768);
        eprintln!(
            "seed6_mr19_sender={} receiver={}",
            serde_json::to_string(&sender_audit).unwrap(),
            serde_json::to_string(&audit).unwrap()
        );
    }

    #[test]
    fn seed6_mr19_invalid_choice_fails_before_first_frame() {
        use crate::c71_bootstrap::{mr19_receiver, Audit};
        use rand::{rngs::StdRng, SeedableRng};
        let mut tape = std::io::Cursor::new(Vec::<u8>::new());
        let mut audit = Audit::default();
        assert!(mr19_receiver(
            &mut tape,
            b"C71S6v01/invalid",
            MR19,
            |_| 2,
            &mut StdRng::seed_from_u64(0),
            &mut audit
        )
        .is_err());
        assert!(audit.sent_frames.is_empty());
        assert_eq!(audit.work.scalar_candidates, 0);
    }

    fn k(x: [u64; 6]) -> K6 {
        K6::from_limbs(x.map(Fp::new))
    }

    fn fixture() -> (Vec<Fp>, Vec<K6>, Vec<K6>, [Fp; 6], [K6; 6], [K6; 6], Vec<K6>, K6) {
        let values = [17, 19, 23].map(Fp::new).to_vec();
        let keys = [[29, 31, 37, 41, 43, 47], [30, 32, 38, 42, 44, 48], [31, 33, 39, 43, 45, 49]]
            .map(k)
            .to_vec();
        let tags = [
            [63, 82, 122, 160, 230, 268],
            [68, 89, 133, 175, 253, 295],
            [77, 102, 154, 204, 298, 348],
        ]
        .map(k)
        .to_vec();
        let mask_values = [79, 83, 89, 97, 101, 103].map(Fp::new);
        let mask_keys = [
            [107, 109, 113, 127, 131, 137],
            [108, 110, 114, 128, 132, 138],
            [109, 111, 115, 129, 133, 139],
            [110, 112, 116, 130, 134, 140],
            [111, 113, 117, 131, 135, 141],
            [112, 114, 118, 132, 136, 142],
        ]
        .map(k);
        let mask_tags = [
            [265, 346, 508, 680, 1000, 1164],
            [274, 359, 529, 709, 1045, 1217],
            [287, 378, 560, 752, 1112, 1296],
            [304, 403, 601, 809, 1201, 1401],
            [313, 416, 622, 838, 1246, 1454],
            [318, 423, 633, 853, 1269, 1481],
        ]
        .map(k);
        let challenges =
            [[53, 59, 61, 67, 71, 73], [54, 60, 62, 68, 72, 74], [55, 61, 63, 69, 73, 75]]
                .map(k)
                .to_vec();
        (values, tags, keys, mask_values, mask_tags, mask_keys, challenges, k([2, 3, 5, 7, 11, 13]))
    }

    fn alpha() -> [Fp3; 2] {
        [
            Fp3::new(Fp::new(139), Fp::new(149), Fp::new(151)),
            Fp3::new(Fp::new(157), Fp::new(163), Fp::new(167)),
        ]
    }

    #[test]
    fn seed6_python_vectors_check_before_compress_and_preserve_mac() {
        let (values, tags, keys, mask_values, mask_tags, mask_keys, challenges, delta) = fixture();
        let prover_check = prover_accumulators(ProverRows {
            values: &values,
            tags: &tags,
            mask_values: &mask_values,
            mask_tags: &mask_tags,
            challenges: &challenges,
        })
        .unwrap();
        let verifier_check = verifier_accumulator(VerifierRows {
            keys: &keys,
            mask_keys: &mask_keys,
            challenges: &challenges,
        })
        .unwrap();
        assert_eq!(prover_check.x.0, [3271, 3629, 3753, 4115, 4355, 4475]);
        assert_eq!(prover_check.z.0, [2126494, 1703895, 1184888, 356904, 288203, 196886]);
        assert_eq!(verifier_check.0 .0, [377749, 304594, 221065, 78457, 63436, 45583]);
        verify_relation(delta, &prover_check, &verifier_check).unwrap();
        let called = Cell::new(false);
        let output = check_then_compress(
            ProverRows {
                values: &values,
                tags: &tags,
                mask_values: &mask_values,
                mask_tags: &mask_tags,
                challenges: &challenges,
            },
            VerifierRows { keys: &keys, mask_keys: &mask_keys, challenges: &challenges },
            delta,
            || {
                called.set(true);
                alpha()
            },
        )
        .unwrap();
        assert!(called.get());
        assert_eq!(
            Seed6Work::for_rows(3),
            Seed6Work {
                prover_k6_products: 9,
                prover_k6_base_products: 9,
                prover_k6_adds: 18,
                verifier_k6_products: 9,
                verifier_k6_adds: 9,
                relation_k6_products: 1,
                relation_k6_adds: 1,
                compression_fp3_products: 14,
                compression_fp3_adds: 7,
                masks: 6,
            }
        );
        let buffers = buffer_report(&output);
        assert_eq!(buffers.prover_borrowed_bytes, 648);
        assert_eq!(buffers.verifier_borrowed_bytes, 576);
        assert_eq!(buffers.prover_check_bytes, 96);
        assert_eq!(buffers.verifier_check_bytes, 48);
        assert_eq!(buffers.prover_output_len_bytes, 72);
        assert_eq!(buffers.verifier_output_len_bytes, 96);
        assert!(buffers.prover_output_capacity_bytes >= buffers.prover_output_len_bytes);
        assert!(buffers.verifier_output_capacity_bytes >= buffers.verifier_output_len_bytes);
        assert_eq!(output.delta.0, [11685, 9435, 6447]);
        let expected_keys = [[60540, 48936, 35376], [62096, 50180, 36302], [63652, 51424, 37228]];
        let expected_tags =
            [[259185, 209331, 144975], [284111, 229445, 158795], [332407, 268429, 185509]];
        for i in 0..3 {
            assert_eq!(output.keys[i].0, expected_keys[i]);
            assert_eq!(output.tags[i].0, expected_tags[i]);
            assert_eq!(
                output.tags[i].fp3(),
                output.keys[i].fp3() + output.delta.fp3().mul_base(values[i])
            );
            assert_eq!(tags[i], keys[i].add(delta.mul_base(values[i])));
        }
    }

    #[test]
    fn seed6_rejects_before_alpha_and_rejects_zero_compressed_key() {
        let (values, mut tags, keys, mask_values, mask_tags, mask_keys, challenges, delta) =
            fixture();
        tags[0] = tags[0].add(K6::basis(0));
        let called = Cell::new(false);
        let error = check_then_compress(
            ProverRows {
                values: &values,
                tags: &tags,
                mask_values: &mask_values,
                mask_tags: &mask_tags,
                challenges: &challenges,
            },
            VerifierRows { keys: &keys, mask_keys: &mask_keys, challenges: &challenges },
            delta,
            || {
                called.set(true);
                alpha()
            },
        )
        .unwrap_err();
        assert_eq!(error, Seed6Error::CorrelationCheck);
        assert!(!called.get());

        let (_, tags, keys, mask_values, mask_tags, mask_keys, challenges, delta) = fixture();
        let error = check_then_compress(
            ProverRows {
                values: &values,
                tags: &tags,
                mask_values: &mask_values,
                mask_tags: &mask_tags,
                challenges: &challenges,
            },
            VerifierRows { keys: &keys, mask_keys: &mask_keys, challenges: &challenges },
            delta,
            || [Fp3::ZERO; 2],
        )
        .unwrap_err();
        assert_eq!(error, Seed6Error::ZeroCompressedKey);
    }

    #[test]
    fn seed6_codec_is_strict_for_every_limb() {
        let value = k([2, 3, 5, 7, 11, 13]);
        assert_eq!(K6::decode(&value.encode()).unwrap(), value);
        assert_eq!(K6::decode(&value.encode()[..47]), Err(Seed6Error::WrongLength));
        for limb in 0..LIMBS {
            let mut encoded = value.encode();
            encoded[8 * limb..8 * limb + 8].copy_from_slice(&P.to_le_bytes());
            assert_eq!(K6::decode(&encoded), Err(Seed6Error::NonCanonicalLimb(limb)));
        }
    }

    #[test]
    fn seed6_rejects_each_data_and_mask_limb_before_alpha() {
        for row in 0..3 {
            for limb in 0..LIMBS {
                let (values, mut tags, keys, mask_values, mask_tags, mask_keys, challenges, delta) =
                    fixture();
                tags[row].0[limb] = (Fp::new(tags[row].0[limb]) + Fp::ONE).value();
                let called = Cell::new(false);
                let result = check_then_compress(
                    ProverRows {
                        values: &values,
                        tags: &tags,
                        mask_values: &mask_values,
                        mask_tags: &mask_tags,
                        challenges: &challenges,
                    },
                    VerifierRows { keys: &keys, mask_keys: &mask_keys, challenges: &challenges },
                    delta,
                    || {
                        called.set(true);
                        alpha()
                    },
                );
                assert_eq!(result.unwrap_err(), Seed6Error::CorrelationCheck);
                assert!(!called.get());
            }
        }
        for row in 0..MASKS {
            for limb in 0..LIMBS {
                let (values, tags, keys, mask_values, mut mask_tags, mask_keys, challenges, delta) =
                    fixture();
                mask_tags[row].0[limb] = (Fp::new(mask_tags[row].0[limb]) + Fp::ONE).value();
                let called = Cell::new(false);
                let result = check_then_compress(
                    ProverRows {
                        values: &values,
                        tags: &tags,
                        mask_values: &mask_values,
                        mask_tags: &mask_tags,
                        challenges: &challenges,
                    },
                    VerifierRows { keys: &keys, mask_keys: &mask_keys, challenges: &challenges },
                    delta,
                    || {
                        called.set(true);
                        alpha()
                    },
                );
                assert_eq!(result.unwrap_err(), Seed6Error::CorrelationCheck);
                assert!(!called.get());
            }
        }
    }

    #[test]
    fn seed6_k6_multiplication_reduces_and_uses_v_squared_seven() {
        // Seven remains nonsquare in the odd-degree extension Fp3.
        assert_eq!(Fp::new(7).pow((P - 1) / 2), Fp::new(P - 1));
        let near_p = k([P - 1, P - 2, P - 3, P - 4, P - 5, P - 6]);
        let other = k([P - 7, P - 8, P - 9, P - 10, P - 11, P - 12]);
        assert_eq!(near_p.mul(other), k([2135, 1742, 1187, 338, 278, 182]));
        assert_eq!(K6::basis(3).mul(K6::basis(3)), k([7, 0, 0, 0, 0, 0]));
    }
}

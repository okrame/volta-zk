//! Carrier-independent C7 terminal transfer over `Fp3`.
//!
//! This is the smallest executable seam for the Lean equation
//! `k = m + Delta*x`. It does not instantiate PCG/VOLE or a PCS prover.

use volta_field::{Fp, Fp2, Fp3, Fp3DecodeError};
use volta_pcg::SubVole;

const BASIS: [Fp3; 3] =
    [Fp3::ONE, Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO), Fp3::new(Fp::ZERO, Fp::ZERO, Fp::ONE)];

/// Algebraic lift of nine distinct sVOLEs from three independent Fp2 pools.
/// Rows select the plaintext limb, columns select the Delta coordinate.
/// The caller must burn all nine entries before sending the six base-field
/// alignment corrections (48 bytes). This function provisions no randomness.
/// B4: coordinated malicious corrections can leave a rank-one base-field
/// residual. Honest correctness is not full-Fp3 active authentication security;
/// see `coordinated_alignment_leaves_only_one_secret_coordinate` below.
/// B5 classifies the general affine residual and rejects this unchecked
/// interface as an actively secure full-Fp3 correlation converter. Hashing,
/// changing basis or repeating linear checks under the same Delta is no repair.
/// See docs/c7.1-gemma31b-design.md, "Esito B5"; diagnostic use only.
pub fn c7_fp3_lift_prover(rows: [[SubVole; 3]; 3]) -> ([Fp; 6], C7Fp3ProverAuthed) {
    let mut corrections = [Fp::ZERO; 6];
    let mut result = C7Fp3ProverAuthed::ZERO;
    for (j, row) in rows.iter().enumerate() {
        corrections[2 * j] = row[0].r - row[1].r;
        corrections[2 * j + 1] = row[0].r - row[2].r;
        result = result.add(
            C7Fp3ProverAuthed::new(
                Fp3::from_base(row[0].r),
                Fp3::new(row[0].m.c0, row[1].m.c0, row[2].m.c0),
            )
            .scale(BASIS[j]),
        );
    }
    (corrections, result)
}

/// Verifier half under Delta=(Delta_0.c0, Delta_1.c0, Delta_2.c0).
/// The Fp2 second tag coordinates are not reinterpreted as cubic coordinates.
/// This identity does not prove security of the multi-pool composition.
pub fn c7_fp3_lift_verifier(
    rows: [[Fp2; 3]; 3],
    delta: Fp3,
    corrections: [Fp; 6],
) -> C7Fp3VerifierKey {
    let mut result = C7Fp3VerifierKey::ZERO;
    for (j, row) in rows.iter().enumerate() {
        result = result.add(
            C7Fp3VerifierKey::new(Fp3::new(
                row[0].c0,
                row[1].c0 + delta.c1 * corrections[2 * j],
                row[2].c0 + delta.c2 * corrections[2 * j + 1],
            ))
            .scale(BASIS[j]),
        );
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3ProverAuthed {
    pub x: Fp3,
    pub m: Fp3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3VerifierKey {
    pub k: Fp3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3TransferCorrection(Fp3);

impl C7Fp3ProverAuthed {
    pub const ZERO: Self = Self { x: Fp3::ZERO, m: Fp3::ZERO };

    #[inline]
    pub const fn new(x: Fp3, m: Fp3) -> Self {
        Self { x, m }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.x + rhs.x, self.m + rhs.m)
    }

    #[inline]
    pub fn scale(self, coefficient: Fp3) -> Self {
        Self::new(coefficient * self.x, coefficient * self.m)
    }
}

impl C7Fp3VerifierKey {
    pub const ZERO: Self = Self { k: Fp3::ZERO };

    #[inline]
    pub const fn new(k: Fp3) -> Self {
        Self { k }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.k + rhs.k)
    }

    #[inline]
    pub fn scale(self, coefficient: Fp3) -> Self {
        Self::new(coefficient * self.k)
    }
}

impl C7Fp3TransferCorrection {
    pub const ENCODED_BYTES: usize = Fp3::ENCODED_BYTES;

    #[inline]
    pub const fn new(value: Fp3) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn value(self) -> Fp3 {
        self.0
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; Self::ENCODED_BYTES] {
        self.0.to_bytes()
    }

    #[inline]
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, Fp3DecodeError> {
        Fp3::from_bytes(encoded).map(Self)
    }
}

/// Provider half of transfer-into-MAC. `Delta` is deliberately absent.
#[inline]
pub fn c7_fp3_transfer_prover(
    correlation: C7Fp3ProverAuthed,
    target: Fp3,
) -> (C7Fp3TransferCorrection, C7Fp3ProverAuthed) {
    (
        C7Fp3TransferCorrection::new(target - correlation.x),
        C7Fp3ProverAuthed::new(target, correlation.m),
    )
}

/// Verifier half of the same transfer under one shared extension-field Delta.
#[inline]
pub fn c7_fp3_transfer_verifier(
    correlation_key: C7Fp3VerifierKey,
    delta: Fp3,
    correction: C7Fp3TransferCorrection,
) -> C7Fp3VerifierKey {
    C7Fp3VerifierKey::new(correlation_key.k + delta * correction.value())
}

/// Pure algebra for one ordered product batch. The caller must bind every
/// triple before sampling `lambda`, and owns transcript phase/recording.
pub fn c7_fp3_product_batch_prover(
    triples: impl IntoIterator<Item = [C7Fp3ProverAuthed; 3]>,
    mask: C7Fp3ProverAuthed,
    lambda: Fp3,
) -> [Fp3; 2] {
    let (mut a, mut b, mut power) = (mask.x, mask.m, Fp3::ONE);
    for [x, y, z] in triples {
        a += power * (x.x * y.m + y.x * x.m - z.m);
        b += power * x.m * y.m;
        power = power * lambda;
    }
    [a, b]
}

/// Verifier half of [`c7_fp3_product_batch_prover`] under `k=m+Delta*x`.
pub fn c7_fp3_product_batch_verify(
    triples: impl IntoIterator<Item = [C7Fp3VerifierKey; 3]>,
    mask: C7Fp3VerifierKey,
    wire: [Fp3; 2],
    lambda: Fp3,
    delta: Fp3,
) -> bool {
    let (mut expected, mut power) = (mask.k, Fp3::ONE);
    for [x, y, z] in triples {
        expected += power * (x.k * y.k - delta * z.k);
        power = power * lambda;
    }
    wire[1] + delta * wire[0] == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, P};

    fn fp3(a: u64, b: u64, c: u64) -> Fp3 {
        Fp3::new(Fp::new(a), Fp::new(b), Fp::new(c))
    }

    fn correlation(delta: Fp3, x: Fp3, m: Fp3) -> (C7Fp3ProverAuthed, C7Fp3VerifierKey) {
        (C7Fp3ProverAuthed::new(x, m), C7Fp3VerifierKey::new(m + delta * x))
    }

    fn valid(delta: Fp3, prover: C7Fp3ProverAuthed, verifier: C7Fp3VerifierKey) -> bool {
        verifier.k == prover.m + delta * prover.x
    }

    #[test]
    fn product_batch_shared_algebra_accepts_and_rejects_mutation() {
        let delta = fp3(17, 19, 23);
        let lambda = fp3(29, 31, 37);
        let authed = |x, m| (C7Fp3ProverAuthed::new(x, m), C7Fp3VerifierKey::new(m + delta * x));
        let (x0, kx0) = authed(fp3(2, 3, 5), fp3(7, 11, 13));
        let (y0, ky0) = authed(fp3(17, 19, 23), fp3(29, 31, 37));
        let (z0, kz0) = authed(x0.x * y0.x, fp3(41, 43, 47));
        let (x1, kx1) = authed(fp3(53, 59, 61), fp3(67, 71, 73));
        let (y1, ky1) = authed(fp3(79, 83, 89), fp3(97, 101, 103));
        let (z1, kz1) = authed(x1.x * y1.x, fp3(107, 109, 113));
        let (mask, mask_key) = authed(fp3(127, 131, 137), fp3(139, 149, 151));
        let prover = [[x0, y0, z0], [x1, y1, z1]];
        let verifier = [[kx0, ky0, kz0], [kx1, ky1, kz1]];
        let wire = c7_fp3_product_batch_prover(prover, mask, lambda);
        assert!(c7_fp3_product_batch_verify(verifier, mask_key, wire, lambda, delta));
        let mut bad = wire;
        bad[0] += Fp3::ONE;
        assert!(!c7_fp3_product_batch_verify(verifier, mask_key, bad, lambda, delta));
    }

    #[test]
    fn transfer_codec_and_multi_commit_linearity_share_one_delta() {
        let delta = fp3(17, 19, 23);
        let (corr0, key0) = correlation(delta, fp3(1, 2, 3), fp3(5, 7, 11));
        let (corr1, key1) = correlation(delta, fp3(13, 17, 19), fp3(23, 29, 31));
        let (wire0, auth0) = c7_fp3_transfer_prover(corr0, fp3(37, 41, 43));
        let (wire1, auth1) = c7_fp3_transfer_prover(corr1, fp3(47, 53, 59));
        let corrected0 = c7_fp3_transfer_verifier(key0, delta, wire0);
        let corrected1 = c7_fp3_transfer_verifier(key1, delta, wire1);
        assert!(valid(delta, auth0, corrected0));
        assert!(valid(delta, auth1, corrected1));

        let beta0 = fp3(61, 67, 71);
        let beta1 = fp3(73, 79, 83);
        let batched_auth = auth0.scale(beta0).add(auth1.scale(beta1));
        let batched_key = corrected0.scale(beta0).add(corrected1.scale(beta1));
        assert!(valid(delta, batched_auth, batched_key));

        let encoded = wire0.to_bytes();
        assert_eq!(encoded.len(), 24);
        assert_eq!(C7Fp3TransferCorrection::from_bytes(&encoded), Ok(wire0));
        for limb in 0..3 {
            let mut noncanonical = encoded;
            noncanonical[limb * 8..(limb + 1) * 8].copy_from_slice(&P.to_le_bytes());
            assert!(C7Fp3TransferCorrection::from_bytes(&noncanonical).is_err());

            let mut mutated = wire0.value();
            match limb {
                0 => mutated.c0 += Fp::ONE,
                1 => mutated.c1 += Fp::ONE,
                _ => mutated.c2 += Fp::ONE,
            }
            let wrong =
                c7_fp3_transfer_verifier(key0, delta, C7Fp3TransferCorrection::new(mutated));
            assert!(!valid(delta, auth0, wrong));
        }
    }

    #[test]
    fn nine_svoles_lift_to_one_cubic_delta_and_detect_alignment_mutations() {
        let deltas = [
            Fp2::new(Fp::new(17), Fp::new(19)),
            Fp2::new(Fp::new(23), Fp::new(29)),
            Fp2::new(Fp::new(31), Fp::new(37)),
        ];
        let delta = Fp3::new(deltas[0].c0, deltas[1].c0, deltas[2].c0);
        let rows = std::array::from_fn(|j| {
            std::array::from_fn(|i| SubVole {
                r: Fp::new((100 * j + 7 * i + 1) as u64),
                m: Fp2::new(Fp::new((13 * j + i + 5) as u64), Fp::new(41)),
            })
        });
        let keys = std::array::from_fn(|j| {
            std::array::from_fn(|i| rows[j][i].m + deltas[i].mul_base(rows[j][i].r))
        });
        let (wire, auth) = c7_fp3_lift_prover(rows);
        let key = c7_fp3_lift_verifier(keys, delta, wire);
        assert!(valid(delta, auth, key));
        assert_eq!(auth.x, fp3(1, 101, 201));
        for i in 0..6 {
            let mut bad = wire;
            bad[i] += Fp::ONE;
            assert!(!valid(delta, auth, c7_fp3_lift_verifier(keys, delta, bad)));
        }
        let (correction, transferred) = c7_fp3_transfer_prover(auth, fp3(43, 47, 53));
        assert!(valid(delta, transferred, c7_fp3_transfer_verifier(key, delta, correction)));
    }

    #[test]
    fn coordinated_alignment_leaves_only_one_secret_coordinate() {
        // A primitive counterexample, not an end-to-end matrix forgery. The
        // prover chooses s and guess without reading any verifier secret.
        let s = fp3(43, 47, 53);
        let guess = Fp::new(17);
        let rows = std::array::from_fn(|j| {
            std::array::from_fn(|i| SubVole {
                r: Fp::new((100 * j + 7 * i + 1) as u64),
                m: Fp2::new(Fp::new((13 * j + i + 5) as u64), Fp::new(41)),
            })
        });
        let (mut wire, auth) = c7_fp3_lift_prover(rows);
        for (j, limb) in [s.c0, s.c1, s.c2].into_iter().enumerate() {
            wire[2 * j] += limb;
            wire[2 * j + 1] += limb;
        }
        // Transfer the nonzero anchor-defined value -s, then claim its MAC
        // authenticates zero. All six altered corrections remain canonical.
        let (transfer, nonzero) = c7_fp3_transfer_prover(auth, -s);
        assert_ne!(nonzero.x, Fp3::ZERO);
        let claimed_zero_tag = auth.m - Fp3::from_base(guess) * s;
        for a in [0, 17, 18] {
            for (b, c) in [(0, 1), (23, 31), (101, 103)] {
                let deltas = [
                    Fp2::new(Fp::new(a), Fp::new(19)),
                    Fp2::new(Fp::new(b), Fp::new(29)),
                    Fp2::new(Fp::new(c), Fp::new(37)),
                ];
                let delta = Fp3::new(deltas[0].c0, deltas[1].c0, deltas[2].c0);
                let keys = std::array::from_fn(|j| {
                    std::array::from_fn(|i| rows[j][i].m + deltas[i].mul_base(rows[j][i].r))
                });
                let lifted = c7_fp3_lift_verifier(keys, delta, wire);
                let checked = c7_fp3_transfer_verifier(lifted, delta, transfer);
                assert_eq!(checked.k - claimed_zero_tag, Fp3::from_base(guess - deltas[0].c0) * s);
                assert_eq!(checked.k == claimed_zero_tag, a == 17);
            }
        }
    }

    #[test]
    fn malicious_lift_realizes_every_base_linear_residual_map() {
        let rows = std::array::from_fn(|j| {
            std::array::from_fn(|i| SubVole {
                r: Fp::new((100 * j + 7 * i + 1) as u64),
                m: Fp2::new(Fp::new((13 * j + i + 5) as u64), Fp::new(41)),
            })
        });
        let (honest_wire, auth) = c7_fp3_lift_prover(rows);
        // The prover picks columns and offset before Delta. This realizes
        // b + A*Delta against a claimed zero, using the actual lift/transfer.
        let residual = |columns: [Fp3; 3], offset: Fp3, delta: Fp3| {
            let x = columns[0];
            let e1 = BASIS[1].inv() * columns[1] - x;
            let e2 = BASIS[2].inv() * columns[2] - x;
            let mut wire = honest_wire;
            for (j, (a, b)) in [e1.c0, e1.c1, e1.c2]
                .into_iter()
                .zip([e2.c0, e2.c1, e2.c2])
                .enumerate()
            {
                wire[2 * j] += a;
                wire[2 * j + 1] += b;
            }
            let deltas = [delta.c0, delta.c1, delta.c2];
            let keys = std::array::from_fn(|j| {
                std::array::from_fn(|i| {
                    rows[j][i].m + Fp2::new(deltas[i], Fp::new(29)).mul_base(rows[j][i].r)
                })
            });
            let (transfer, _) = c7_fp3_transfer_prover(auth, x);
            let key = c7_fp3_transfer_verifier(
                c7_fp3_lift_verifier(keys, delta, wire), delta, transfer,
            );
            key.k - (auth.m - offset)
        };
        // All nine elementary matrices: not just the coordinated B4 family.
        for row in 0..3 {
            for col in 0..3 {
                let mut columns = [Fp3::ZERO; 3];
                columns[col] = BASIS[row];
                for (i, delta) in BASIS.into_iter().enumerate() {
                    assert_eq!(residual(columns, Fp3::ZERO, delta),
                        if i == col { BASIS[row] } else { Fp3::ZERO });
                }
            }
        }
        // Rank 1, 2 and 3 fibers, including zero/nonzero coordinates and
        // both passing and failing guesses. Every anchor target is 1 != 0.
        for rank in 1..=3 {
            let columns = std::array::from_fn(|i| if i < rank { BASIS[i] } else { Fp3::ZERO });
            for a in [0, 1, 17, 18] {
                for b in [0, 1, 17, 18] {
                    for c in [0, 1, 17, 18] {
                        let value = residual(columns, -fp3(17, 0, 0), fp3(a, b, c));
                        assert_eq!(value, fp3(a, if rank > 1 { b } else { 0 },
                            if rank > 2 { c } else { 0 }) - fp3(17, 0, 0));
                        assert_eq!(value == Fp3::ZERO,
                            a == 17 && (rank < 2 || b == 0) && (rank < 3 || c == 0));
                    }
                }
            }
        }
        // Existing add/scale checks preserve the common secret factor.
        // They do not turn three checks into three independent key guesses.
        for a in [17, 18] {
            let delta = fp3(a, 23, 31);
            let mut batch = C7Fp3VerifierKey::ZERO;
            let mut weighted_shift = Fp3::ZERO;
            for (i, s) in BASIS.into_iter().enumerate() {
                let r = residual([-s, Fp3::ZERO, Fp3::ZERO], s * Fp3::from_base(Fp::new(17)), delta);
                let coefficient = fp3(i as u64 + 1, 7, 11);
                batch = batch.add(C7Fp3VerifierKey::new(r).scale(coefficient));
                weighted_shift += coefficient * s;
                assert_eq!(r == Fp3::ZERO, a == 17);
            }
            assert_ne!(weighted_shift, Fp3::ZERO);
            assert_eq!(batch.k, Fp3::from_base(Fp::new(17) - delta.c0) * weighted_shift);
            assert_eq!(batch.k == Fp3::ZERO, a == 17);
        }
    }

    #[test]
    fn cubic_lift_consumes_three_real_aes_pool_pairs() {
        use volta_pcg::{
            expand_phase_b_production, GgmPrg, PhaseAParams, ResponseAuthorizationStore,
            SessionBinding,
        };
        let root = std::env::temp_dir().join(format!(
            "volta-c71-lift-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = ResponseAuthorizationStore::new(&root).unwrap();
        // These are real OT/AES state machines with deliberately tiny LPN
        // tuples. This checks the algebra and plumbing, not PCG security.
        let mut pools: Vec<_> = (0..3)
            .map(|lane| {
                let binding = SessionBinding::new([0x71; 32], [0x72; 32], [lane + 1; 32]).unwrap();
                let setup = expand_phase_b_production(
                    &store,
                    binding,
                    6,
                    0,
                    PhaseAParams::tiny_for_test(6),
                )
                .unwrap();
                assert!(setup.expansion.consistency.ok);
                assert_eq!(setup.expansion.setup.params.ggm_prg, GgmPrg::Aes128Mmo);
                assert!(store.reserve(&binding).is_err());
                setup.expansion
            })
            .collect();
        let delta = Fp3::new(
            pools[0].verifier_delta.c0,
            pools[1].verifier_delta.c0,
            pools[2].verifier_delta.c0,
        );
        for _ in 0..2 {
            let rows = std::array::from_fn(|_| {
                std::array::from_fn(|lane| pools[lane].prover.subs.pop().unwrap())
            });
            let keys = std::array::from_fn(|_| {
                std::array::from_fn(|lane| pools[lane].verifier.sub_keys.pop().unwrap())
            });
            let (wire, auth) = c7_fp3_lift_prover(rows);
            assert!(valid(delta, auth, c7_fp3_lift_verifier(keys, delta, wire)));
        }
        assert!(pools
            .iter()
            .all(|pool| pool.prover.subs.is_empty() && pool.verifier.sub_keys.is_empty()));
        std::fs::remove_dir_all(root).unwrap();
    }
}

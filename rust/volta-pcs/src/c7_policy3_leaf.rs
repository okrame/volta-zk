//! C7 Policy-3 salted leaf commitment reference.
//!
//! This is the concrete leaf primitive only.  It does not claim that a
//! privately verified code opening or the C7 malicious-DV theorem already
//! exists.  The private checker must prove this exact permutation transcript
//! under fresh response-local authentication without serializing `salt` or
//! `payload`.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_16, Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use volta_field::{Fp, P};

pub const C7_LEAF_SYMBOLS: usize = 141;
pub const C7_LEAF_SALT_BYTES: usize = 32;
pub const C7_LEAF_DIGEST_LIMBS: usize = 4;
pub const C7_LEAF_DIGEST_BYTES: usize = 32;
pub const C7_LEAF_POSEIDON_WIDTH: usize = 16;
pub const C7_LEAF_POSEIDON_RATE: usize = 12;
pub const C7_LEAF_POSEIDON_PERMUTATIONS: usize = 14;
pub const C7_LEAF_POSEIDON_SBOXES_PER_PERMUTATION: usize = 8 * 16 + 22;
pub const C7_LEAF_SECRET_MULTIPLICATIONS_PER_SBOX: usize = 4;
pub const C7_LEAF_SECRET_MULTIPLICATIONS: usize = C7_LEAF_POSEIDON_PERMUTATIONS
    * C7_LEAF_POSEIDON_SBOXES_PER_PERMUTATION
    * C7_LEAF_SECRET_MULTIPLICATIONS_PER_SBOX;
pub const C7_LEAF_PRIVATE_INPUT_SYMBOLS: usize = C7_LEAF_SYMBOLS + 8;
pub const C7_LEAF_PRIVATE_INPUT_CORRECTION_BYTES: usize = C7_LEAF_PRIVATE_INPUT_SYMBOLS * 8;

const C7_LEAF_ABSORBED_FIELDS: usize = 166;
const C7_LEAF_PADDED_FIELDS: usize = C7_LEAF_POSEIDON_RATE * C7_LEAF_POSEIDON_PERMUTATIONS;
const C7_LEAF_DOMAIN: u64 = u64::from_le_bytes(*b"C7LCv001");
const C7_LEAF_ROOT_CONTEXT: &str = "volta-zk/c7/policy3/leaf-root-context/v1";
const C7_LEAF_SALT_DERIVATION_CONTEXT: &str = "volta-zk/c7/policy3/leaf-salt/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum C7LeafPlane {
    PackedWeights = 1,
    ResponseBoundary = 2,
    KvPredecessor = 3,
    KvSuccessor = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7LeafMetadata {
    /// Public digest of `(layout_digest, commitment_nonce, plane)`.
    pub root_context: [u8; 32],
    pub plane: C7LeafPlane,
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// Exact number of logical symbols in this plane.
    pub total_symbols: u64,
    /// Number of non-padding symbols in the fixed 141-symbol payload.
    pub payload_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7LeafDigest(pub [Fp; C7_LEAF_DIGEST_LIMBS]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C7LeafError {
    ZeroRootContext,
    Geometry,
    PayloadLength,
    NonzeroPadding,
    NoncanonicalDigest,
}

/// Bind one public layout and nonce to the root before hashing any leaf.
/// The future root codec must recompute this value rather than accepting an
/// arbitrary context supplied by the prover.
pub fn c7_leaf_root_context(
    layout_digest: [u8; 32],
    commitment_nonce: [u8; 32],
    plane: C7LeafPlane,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(C7_LEAF_ROOT_CONTEXT);
    hasher.update(&layout_digest);
    hasher.update(&commitment_nonce);
    hasher.update(&(plane as u32).to_le_bytes());
    *hasher.finalize().as_bytes()
}

impl C7LeafDigest {
    pub fn to_bytes(self) -> [u8; C7_LEAF_DIGEST_BYTES] {
        let mut out = [0; C7_LEAF_DIGEST_BYTES];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&limb.value().to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: [u8; C7_LEAF_DIGEST_BYTES]) -> Result<Self, C7LeafError> {
        let mut limbs = [Fp::ZERO; C7_LEAF_DIGEST_LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let value = u64::from_le_bytes(chunk.try_into().expect("eight-byte digest limb"));
            if value >= P {
                return Err(C7LeafError::NoncanonicalDigest);
            }
            *limb = Fp::new(value);
        }
        Ok(Self(limbs))
    }
}

/// Derive one provider-private salt from a root-local secret seed.  The
/// root context and complete tree geometry prevent cross-root/position
/// reuse; the seed and derived salt are never serialized.
pub fn c7_leaf_salt(
    root_salt_seed: [u8; 32],
    metadata: C7LeafMetadata,
) -> [u8; C7_LEAF_SALT_BYTES] {
    let key = blake3::derive_key(C7_LEAF_SALT_DERIVATION_CONTEXT, &root_salt_seed);
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&metadata.root_context);
    hasher.update(&(metadata.plane as u32).to_le_bytes());
    hasher.update(&metadata.leaf_index.to_le_bytes());
    hasher.update(&metadata.leaf_count.to_le_bytes());
    hasher.update(&metadata.total_symbols.to_le_bytes());
    hasher.update(&metadata.payload_len.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn absorb_u32_words(out: &mut [Goldilocks], cursor: &mut usize, bytes: &[u8; 32]) {
    for chunk in bytes.chunks_exact(4) {
        out[*cursor] =
            Goldilocks::from_u32(u32::from_le_bytes(chunk.try_into().expect("four-byte word")));
        *cursor += 1;
    }
}

/// Reusable permutation owner.  Construct one per worker and reuse it across
/// the streaming setup/opening; `commit` performs no heap allocation.
pub struct C7LeafCommitter {
    permutation: Poseidon2Goldilocks<16>,
}

impl Default for C7LeafCommitter {
    fn default() -> Self {
        Self { permutation: default_goldilocks_poseidon2_16() }
    }
}

impl C7LeafCommitter {
    /// Commit one canonical logical leaf.  The salt is provider-private and
    /// parsed injectively as eight `u32` limbs, preserving the exact 256-bit
    /// salt space used by the C7 privacy census.
    pub fn commit(
        &self,
        metadata: C7LeafMetadata,
        salt: [u8; C7_LEAF_SALT_BYTES],
        payload: &[Fp; C7_LEAF_SYMBOLS],
    ) -> Result<C7LeafDigest, C7LeafError> {
        if metadata.root_context == [0; 32] {
            return Err(C7LeafError::ZeroRootContext);
        }
        let leaf_symbols = C7_LEAF_SYMBOLS as u64;
        let expected_leaf_count = metadata.total_symbols / leaf_symbols
            + u64::from(metadata.total_symbols % leaf_symbols != 0);
        if metadata.total_symbols == 0
            || metadata.leaf_count != expected_leaf_count
            || metadata.leaf_index >= metadata.leaf_count
        {
            return Err(C7LeafError::Geometry);
        }
        let payload_len =
            usize::try_from(metadata.payload_len).map_err(|_| C7LeafError::PayloadLength)?;
        let leaf_start =
            metadata.leaf_index.checked_mul(leaf_symbols).ok_or(C7LeafError::Geometry)?;
        let expected_payload_len = usize::try_from(
            metadata
                .total_symbols
                .checked_sub(leaf_start)
                .ok_or(C7LeafError::Geometry)?
                .min(leaf_symbols),
        )
        .map_err(|_| C7LeafError::PayloadLength)?;
        if payload_len != expected_payload_len {
            return Err(C7LeafError::PayloadLength);
        }
        if payload[payload_len..].iter().any(|value| *value != Fp::ZERO) {
            return Err(C7LeafError::NonzeroPadding);
        }

        let mut input = [Goldilocks::ZERO; C7_LEAF_PADDED_FIELDS];
        let mut cursor = 0;
        absorb_u32_words(&mut input, &mut cursor, &metadata.root_context);
        for value in [
            metadata.plane as u32,
            metadata.leaf_index as u32,
            (metadata.leaf_index >> 32) as u32,
            metadata.leaf_count as u32,
            (metadata.leaf_count >> 32) as u32,
            metadata.total_symbols as u32,
            (metadata.total_symbols >> 32) as u32,
            metadata.payload_len,
            (C7_LEAF_SYMBOLS - payload_len) as u32,
        ] {
            input[cursor] = Goldilocks::from_u32(value);
            cursor += 1;
        }
        absorb_u32_words(&mut input, &mut cursor, &salt);
        for value in payload {
            input[cursor] = Goldilocks::new(value.value());
            cursor += 1;
        }
        debug_assert_eq!(cursor, C7_LEAF_ABSORBED_FIELDS);
        input[cursor] = Goldilocks::ONE;

        let mut state = [Goldilocks::ZERO; C7_LEAF_POSEIDON_WIDTH];
        state[C7_LEAF_POSEIDON_RATE] = Goldilocks::new(C7_LEAF_DOMAIN);
        state[C7_LEAF_POSEIDON_RATE + 1] = Goldilocks::from_u32(C7_LEAF_SYMBOLS as u32);
        state[C7_LEAF_POSEIDON_RATE + 2] = Goldilocks::from_u32(C7_LEAF_POSEIDON_WIDTH as u32);
        state[C7_LEAF_POSEIDON_RATE + 3] = Goldilocks::from_u32(C7_LEAF_POSEIDON_RATE as u32);
        for block in input.chunks_exact(C7_LEAF_POSEIDON_RATE) {
            for (state_limb, input_limb) in state[..C7_LEAF_POSEIDON_RATE].iter_mut().zip(block) {
                *state_limb += *input_limb;
            }
            self.permutation.permute_mut(&mut state);
        }

        Ok(C7LeafDigest(core::array::from_fn(|index| Fp::new(state[index].as_canonical_u64()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (C7LeafMetadata, [u8; 32], [Fp; C7_LEAF_SYMBOLS]) {
        let plane = C7LeafPlane::PackedWeights;
        let metadata = C7LeafMetadata {
            root_context: c7_leaf_root_context([0x31; 32], [0x57; 32], plane),
            plane,
            leaf_index: 4,
            leaf_count: 5,
            total_symbols: 703,
            payload_len: 139,
        };
        let salt = core::array::from_fn(|i| (7 * i + 11) as u8);
        let payload = core::array::from_fn(|i| {
            if i < 139 {
                Fp::from_i64((i as i64 % 31) - 15)
            } else {
                Fp::ZERO
            }
        });
        (metadata, salt, payload)
    }

    #[test]
    fn leaf_commitment_known_answer_and_canonical_codec() {
        let (metadata, salt, payload) = fixture();
        let digest = C7LeafCommitter::default().commit(metadata, salt, &payload).unwrap();
        assert_eq!(
            digest.0,
            [
                Fp::new(0xc194_b4e7_35db_8f2d),
                Fp::new(0xbbe8_08ec_a777_ec39),
                Fp::new(0x3ace_d6be_d796_3f68),
                Fp::new(0xd210_99f1_8ee6_c600),
            ]
        );
        assert_eq!(C7LeafDigest::from_bytes(digest.to_bytes()), Ok(digest));
        let mut noncanonical = digest.to_bytes();
        noncanonical[..8].copy_from_slice(&P.to_le_bytes());
        assert_eq!(C7LeafDigest::from_bytes(noncanonical), Err(C7LeafError::NoncanonicalDigest));
    }

    #[test]
    fn metadata_salt_payload_and_padding_are_bound() {
        let (metadata, salt, payload) = fixture();
        let committer = C7LeafCommitter::default();
        let digest = committer.commit(metadata, salt, &payload).unwrap();

        let mut changed_salt = salt;
        changed_salt[0] ^= 1;
        assert_ne!(committer.commit(metadata, changed_salt, &payload).unwrap(), digest);

        let mut changed_payload = payload;
        changed_payload[17] += Fp::ONE;
        assert_ne!(committer.commit(metadata, salt, &changed_payload).unwrap(), digest);

        for changed in [
            C7LeafMetadata { plane: C7LeafPlane::ResponseBoundary, ..metadata },
            C7LeafMetadata {
                root_context: {
                    let mut context = metadata.root_context;
                    context[0] ^= 1;
                    context
                },
                ..metadata
            },
        ] {
            assert_ne!(committer.commit(changed, salt, &payload).unwrap(), digest);
        }

        let mut bad_padding = payload;
        bad_padding[140] = Fp::ONE;
        assert_eq!(
            committer.commit(metadata, salt, &bad_padding),
            Err(C7LeafError::NonzeroPadding)
        );
        let bad_len = C7LeafMetadata { payload_len: 142, ..metadata };
        assert_eq!(committer.commit(bad_len, salt, &payload), Err(C7LeafError::PayloadLength));

        let wrong_count = C7LeafMetadata { leaf_count: metadata.leaf_count + 1, ..metadata };
        assert_eq!(committer.commit(wrong_count, salt, &payload), Err(C7LeafError::Geometry));
        let wrong_total = C7LeafMetadata { total_symbols: metadata.total_symbols + 1, ..metadata };
        assert_eq!(committer.commit(wrong_total, salt, &payload), Err(C7LeafError::PayloadLength));
        let interior_partial = C7LeafMetadata { leaf_index: 0, payload_len: 139, ..metadata };
        assert_eq!(
            committer.commit(interior_partial, salt, &payload),
            Err(C7LeafError::PayloadLength)
        );
        let empty_plane = C7LeafMetadata {
            leaf_index: 0,
            leaf_count: 0,
            total_symbols: 0,
            payload_len: 0,
            ..metadata
        };
        assert_eq!(committer.commit(empty_plane, salt, &payload), Err(C7LeafError::Geometry));

        let bad_geometry = C7LeafMetadata { leaf_index: metadata.leaf_count, ..metadata };
        assert_eq!(committer.commit(bad_geometry, salt, &payload), Err(C7LeafError::Geometry));
        let zero_context = C7LeafMetadata { root_context: [0; 32], ..metadata };
        assert_eq!(
            committer.commit(zero_context, salt, &payload),
            Err(C7LeafError::ZeroRootContext)
        );
    }

    #[test]
    fn private_checker_cost_is_pinned() {
        assert_eq!(C7_LEAF_POSEIDON_PERMUTATIONS, 14);
        assert_eq!(C7_LEAF_SECRET_MULTIPLICATIONS, 8_400);
        assert_eq!(C7_LEAF_PRIVATE_INPUT_CORRECTION_BYTES, 1_192);
    }

    #[test]
    fn root_local_salt_derivation_is_position_bound() {
        let (metadata, _, _) = fixture();
        assert_ne!(
            c7_leaf_root_context([0x30; 32], [0x57; 32], metadata.plane),
            metadata.root_context
        );
        assert_ne!(
            c7_leaf_root_context([0x31; 32], [0x56; 32], metadata.plane),
            metadata.root_context
        );
        let seed = [0x5a; 32];
        let salt = c7_leaf_salt(seed, metadata);
        assert_eq!(
            salt,
            [
                15, 171, 199, 95, 119, 170, 64, 131, 22, 171, 193, 223, 107, 246, 113, 39, 176,
                192, 22, 58, 29, 81, 153, 46, 103, 173, 117, 43, 118, 141, 13, 30,
            ]
        );
        assert_ne!(
            c7_leaf_salt(seed, C7LeafMetadata { leaf_index: metadata.leaf_index - 1, ..metadata }),
            salt
        );
        let mut other_seed = seed;
        other_seed[0] ^= 1;
        assert_ne!(c7_leaf_salt(other_seed, metadata), salt);
    }
}

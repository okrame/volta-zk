//! Fixed-key AES-128-MMO node expansion for the WYKW GGM tree.
//!
//! The public key and correlation-robust transform are preregistered in
//! `docs/fase-d-realpcg-default-design.md`: `sigma(x) = AES_K(x) XOR x`,
//! with `K = 000102...0f`, `tau_0 = 0`, and `tau_1 = 1` in canonical
//! little-endian encoding.  Hardware selection never changes the function.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub(crate) type GgmSeed = [u8; 16];

const FIXED_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GgmPrg {
    #[default]
    #[serde(rename = "aes128-mmo")]
    Aes128Mmo,
    #[serde(rename = "blake3")]
    Blake3,
}

impl GgmPrg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Mmo => "aes128-mmo",
            Self::Blake3 => "blake3",
        }
    }
}

impl fmt::Display for GgmPrg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GgmPrg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "aes128-mmo" => Ok(Self::Aes128Mmo),
            "blake3" => Ok(Self::Blake3),
            _ => Err(format!("invalid GGM PRG {value:?}; expected aes128-mmo or blake3")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AesBackend {
    #[serde(rename = "aes-ni")]
    AesNi,
    #[serde(rename = "armv8-ce")]
    Armv8Ce,
    #[serde(rename = "portable")]
    Portable,
}

impl AesBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AesNi => "aes-ni",
            Self::Armv8Ce => "armv8-ce",
            Self::Portable => "portable",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct GgmEngine {
    prg: GgmPrg,
    aes_backend: AesBackend,
    round_keys: [[u8; 16]; 11],
}

impl GgmEngine {
    pub(crate) fn new(prg: GgmPrg) -> Self {
        Self { prg, aes_backend: detect_aes_backend(), round_keys: expand_key(FIXED_KEY) }
    }

    pub(crate) const fn prg(self) -> GgmPrg {
        self.prg
    }

    pub(crate) const fn aes_backend(self) -> AesBackend {
        self.aes_backend
    }

    pub(crate) fn children(&self, seed: GgmSeed) -> (GgmSeed, GgmSeed) {
        match self.prg {
            GgmPrg::Aes128Mmo => {
                let left_input = seed;
                let mut right_input = seed;
                // tau_1 is integer one in canonical little-endian encoding.
                right_input[0] ^= 1;
                (self.sigma(left_input), self.sigma(right_input))
            }
            GgmPrg::Blake3 => (blake3_child(seed, 0), blake3_child(seed, 1)),
        }
    }

    fn sigma(&self, input: GgmSeed) -> GgmSeed {
        let encrypted = self.encrypt(input);
        xor16(encrypted, input)
    }

    fn encrypt(&self, input: GgmSeed) -> GgmSeed {
        match self.aes_backend {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            AesBackend::AesNi => {
                // SAFETY: construction selects this branch only after the
                // runtime AES feature check succeeds.
                unsafe { encrypt_aesni(input, &self.round_keys) }
            }
            #[cfg(target_arch = "aarch64")]
            AesBackend::Armv8Ce => {
                // SAFETY: construction selects this branch only after the
                // runtime ARM AES feature check succeeds.
                unsafe { encrypt_armv8(input, &self.round_keys) }
            }
            _ => encrypt_portable(input, &self.round_keys),
        }
    }
}

pub(crate) fn detect_aes_backend() -> AesBackend {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("aes") {
        return AesBackend::AesNi;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        return AesBackend::Armv8Ce;
    }
    AesBackend::Portable
}

fn blake3_child(seed: GgmSeed, branch: u8) -> GgmSeed {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta-pcg/phase-b/ggm-prg/blake3/v1");
    hasher.update(&seed);
    let mut tau = [0u8; 16];
    tau[0] = branch;
    hasher.update(&tau);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    out
}

fn xor16(a: GgmSeed, b: GgmSeed) -> GgmSeed {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn expand_key(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut expanded = [0u8; 176];
    expanded[..16].copy_from_slice(&key);
    let mut generated = 16;
    let mut rcon = 0;
    while generated < expanded.len() {
        let mut temp = [
            expanded[generated - 4],
            expanded[generated - 3],
            expanded[generated - 2],
            expanded[generated - 1],
        ];
        if generated % 16 == 0 {
            temp.rotate_left(1);
            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }
            temp[0] ^= RCON[rcon];
            rcon += 1;
        }
        for byte in temp {
            expanded[generated] = expanded[generated - 16] ^ byte;
            generated += 1;
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for (round, out) in round_keys.iter_mut().enumerate() {
        out.copy_from_slice(&expanded[round * 16..(round + 1) * 16]);
    }
    round_keys
}

fn encrypt_portable(mut state: [u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    add_round_key(&mut state, &round_keys[0]);
    for round_key in &round_keys[1..10] {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);
    state
}

fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    state[1] = old[5];
    state[5] = old[9];
    state[9] = old[13];
    state[13] = old[1];
    state[2] = old[10];
    state[6] = old[14];
    state[10] = old[2];
    state[14] = old[6];
    state[3] = old[15];
    state[7] = old[3];
    state[11] = old[7];
    state[15] = old[11];
}

fn xtime(value: u8) -> u8 {
    (value << 1) ^ (0x1b & 0u8.wrapping_sub(value >> 7))
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let i = 4 * column;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        let all = a0 ^ a1 ^ a2 ^ a3;
        state[i] ^= all ^ xtime(a0 ^ a1);
        state[i + 1] ^= all ^ xtime(a1 ^ a2);
        state[i + 2] ^= all ^ xtime(a2 ^ a3);
        state[i + 3] ^= all ^ xtime(a3 ^ a0);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_aesni(input: [u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    use core::arch::x86_64::*;
    let mut state = _mm_loadu_si128(input.as_ptr().cast());
    state = _mm_xor_si128(state, _mm_loadu_si128(round_keys[0].as_ptr().cast()));
    for round_key in &round_keys[1..10] {
        state = _mm_aesenc_si128(state, _mm_loadu_si128(round_key.as_ptr().cast()));
    }
    state = _mm_aesenclast_si128(state, _mm_loadu_si128(round_keys[10].as_ptr().cast()));
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), state);
    out
}

#[cfg(target_arch = "x86")]
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_aesni(input: [u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    use core::arch::x86::*;
    let mut state = _mm_loadu_si128(input.as_ptr().cast());
    state = _mm_xor_si128(state, _mm_loadu_si128(round_keys[0].as_ptr().cast()));
    for round_key in &round_keys[1..10] {
        state = _mm_aesenc_si128(state, _mm_loadu_si128(round_key.as_ptr().cast()));
    }
    state = _mm_aesenclast_si128(state, _mm_loadu_si128(round_keys[10].as_ptr().cast()));
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), state);
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn encrypt_armv8(input: [u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    use core::arch::aarch64::*;
    let mut state = vld1q_u8(input.as_ptr());
    for round_key in &round_keys[..9] {
        state = vaeseq_u8(state, vld1q_u8(round_key.as_ptr()));
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, vld1q_u8(round_keys[9].as_ptr()));
    state = veorq_u8(state, vld1q_u8(round_keys[10].as_ptr()));
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), state);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_aes_matches_fips_197_vector() {
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        assert_eq!(encrypt_portable(input, &expand_key(FIXED_KEY)), expected);
    }

    #[test]
    fn detected_backend_matches_portable_aes() {
        let engine = GgmEngine::new(GgmPrg::Aes128Mmo);
        let input = [0x5a; 16];
        assert_eq!(engine.encrypt(input), encrypt_portable(input, &engine.round_keys));
    }

    #[test]
    fn mmo_zero_seed_matches_fixed_key_vector() {
        // AES-128_K(0), K=000102...0f. Since x=0, MMO sigma(x) is the
        // ciphertext itself.
        let expected_left = [
            0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8,
            0xd8, 0x79,
        ];
        let (left, right) = GgmEngine::new(GgmPrg::Aes128Mmo).children([0u8; 16]);
        assert_eq!(left, expected_left);
        assert_ne!(left, right);
    }

    #[test]
    fn default_is_aes_and_blake3_is_explicit() {
        assert_eq!(GgmPrg::default(), GgmPrg::Aes128Mmo);
        assert_eq!(GgmPrg::default().as_str(), "aes128-mmo");
        assert_ne!(
            GgmEngine::new(GgmPrg::Aes128Mmo).children([0u8; 16]),
            GgmEngine::new(GgmPrg::Blake3).children([0u8; 16])
        );
        assert_eq!("aes128-mmo".parse(), Ok(GgmPrg::Aes128Mmo));
        assert_eq!("blake3".parse(), Ok(GgmPrg::Blake3));
        assert!("auto".parse::<GgmPrg>().is_err());
    }
}

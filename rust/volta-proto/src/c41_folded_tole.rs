//! C4.1 folded-query high-degree typed OLE primitives.
//!
//! A degree-`d` authenticated value is represented by a polynomial whose
//! coefficient at `X^d` is the plaintext and whose evaluation at the
//! verifier-only `Delta` is the verifier key.  The prover stores only the
//! lower coefficients in response slabs; the semantic top coefficient is
//! reconstructed from the Packed16 correction.

use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use volta_accel::{
    AccelError, Backend, C41PackedProverDeviceLot, C41PackedVerifierDeviceLot, DeviceBuffer,
    DeviceSlice, Fp2Repr,
};
use volta_field::{Fp, Fp2, FpStream, P};
use volta_mac::{
    auth_prover, auth_verifier, CorrelationStream, FullCorr, ProverAuthed, ProverSubAuthed,
    Transcript, VerifierCtx, VerifierKey,
};

pub const C41_TYPED_POLYNOMIAL_LANES: usize = 12;
pub const C41_MAX_DEGREE: usize = 12;
pub const C41_SEED_BITS: usize = 1024;
pub const C41_PRG_OUTPUT_BITS: usize = 1 << 20;
pub const C41_PRG_USABLE_BITS: usize = C41_PRG_OUTPUT_BITS - C41_SEED_BITS;
pub const C41_BITS_PER_PACKED_CELL: usize = 17;
pub const C41_DEGREE12_CLOSE_BYTES: usize = 201;
pub const C41_MAX_BRIDGES_PER_RESPONSE: usize = 1_000_000;
pub const C41_VERIFIER_STREAM_CHUNK_CELLS: usize = 4_096;

#[derive(Clone, Debug, Default)]
pub struct C41ProverDiagnostics {
    pub cells: usize,
    pub segments: usize,
    pub bridges: usize,
    pub bridge_sparse_entries: u64,
    pub lot_prepare_download_s: f64,
    pub registration_s: f64,
    pub bridge_build_s: f64,
    pub dense_query_build_s: f64,
    pub dense_query_bytes: u64,
    pub rayon_query_scratch_upper_bytes: u64,
    pub query_upload_s: f64,
    pub bitmap_upload_s: f64,
    pub fused_fold_submit_s: f64,
    pub fold_download_sync_s: f64,
    pub degree12_close_s: f64,
    pub cleanup_s: f64,
}

#[derive(Clone, Debug, Default)]
pub struct C41VerifierDiagnostics {
    pub cells: usize,
    pub segments: usize,
    pub bridges: usize,
    pub chunks: usize,
    pub query_chunk_peak_bytes: u64,
    pub descriptor_build_s: f64,
    pub query_chunk_build_s: f64,
    pub seed_expand_and_stream_fold_s: f64,
    pub degree12_close_s: f64,
}

const C41_CLOSE_MAGIC: &[u8; 8] = b"C41D12\0\0";
const C41_BITNESS_CLOSE_MAGIC: &[u8; 8] = b"C41D02\0\0";
const C41_SETUP_MAGIC: &[u8; 8] = b"C41TS1\0\0";
const C41_SETUP_VERSION: u16 = 1;
const C41_SETUP_ROW_HEADER_BYTES: usize = 9;
// Session 30 is reserved for C4.1. Keep the top three bits clear: the MAC
// allocator uses them to distinguish tags, full-field draws and ledger keys.
const C41_BRIDGE_DOMAIN_BASE: u64 = 0x1E_C4_1000_0000_0000;
const C41_CLOSE_MASK_DOMAIN: u64 = 0x1E_C4_1FFF_FFFF_FFFF;
const C41_PACKED_D_LABEL: &str = "c41_packed_d";
const C41_PACKED_E_LABEL: &str = "c41_packed_e";
const C41_BRIDGE_LABEL: &str = "c41_bridge_correction";
// Coefficients, ascending, of the unique Goldilocks polynomial that is zero
// on 0..=3 and one on 4..=7.
const MAJ7_COEFFICIENTS: [u64; 8] = [
    0,
    15_855_415_735_853_964_137,
    13_578_853_273_319_069_027,
    12_041_624_600_867_853_643,
    3_586_866_902_386_169_178,
    11_119_287_397_397_124_437,
    10_504_395_928_416_638_294,
    7_100_532_439_417_518_568,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41HdProver {
    pub coefficients: [Fp2; C41_MAX_DEGREE + 1],
    pub degree: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41HdVerifier {
    pub key: Fp2,
    pub degree: u8,
}

impl C41HdProver {
    pub fn seed(value: ProverSubAuthed) -> Self {
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        coefficients[0] = value.m;
        coefficients[1] = Fp2::from_base(value.x);
        Self { coefficients, degree: 1 }
    }

    pub fn public(value: Fp2) -> Self {
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        coefficients[1] = value;
        Self { coefficients, degree: 1 }
    }

    pub fn ordinary(value: ProverAuthed) -> Self {
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        coefficients[0] = value.m;
        coefficients[1] = value.x;
        Self { coefficients, degree: 1 }
    }

    pub fn value(self) -> Fp2 {
        self.coefficients[self.degree as usize]
    }

    pub fn eval(self, point: Fp2) -> Fp2 {
        self.coefficients[..=self.degree as usize]
            .iter()
            .rev()
            .fold(Fp2::ZERO, |acc, coefficient| acc * point + *coefficient)
    }

    pub fn add(self, rhs: Self) -> Self {
        self.add_sub(rhs, false)
    }

    pub fn sub(self, rhs: Self) -> Self {
        self.add_sub(rhs, true)
    }

    fn add_sub(mut self, rhs: Self, subtract: bool) -> Self {
        let degree = self.degree.max(rhs.degree);
        if self.degree < degree {
            let shift = usize::from(degree - self.degree);
            for index in (0..=self.degree as usize).rev() {
                self.coefficients[index + shift] = self.coefficients[index];
            }
            self.coefficients[..shift].fill(Fp2::ZERO);
        }
        let offset = usize::from(degree - rhs.degree);
        for index in 0..=rhs.degree as usize {
            let target = &mut self.coefficients[offset + index];
            *target = if subtract {
                *target - rhs.coefficients[index]
            } else {
                *target + rhs.coefficients[index]
            };
        }
        self.degree = degree;
        self
    }

    pub fn scale(mut self, scalar: Fp2) -> Self {
        for coefficient in &mut self.coefficients[..=self.degree as usize] {
            *coefficient = *coefficient * scalar;
        }
        self
    }

    pub fn multiply(self, rhs: Self) -> Result<Self, &'static str> {
        let degree = usize::from(self.degree)
            .checked_add(usize::from(rhs.degree))
            .ok_or("C4.1 polynomial degree overflow")?;
        if degree > C41_MAX_DEGREE {
            return Err("C4.1 typed product exceeds degree 12");
        }
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        for left in 0..=self.degree as usize {
            for right in 0..=rhs.degree as usize {
                coefficients[left + right] += self.coefficients[left] * rhs.coefficients[right];
            }
        }
        Ok(Self { coefficients, degree: degree as u8 })
    }

    pub fn xor(self, rhs: Self) -> Result<Self, &'static str> {
        Ok(self.add(rhs).sub(self.multiply(rhs)?.scale(Fp2::from_base(Fp::new(2)))))
    }
}

impl C41HdVerifier {
    pub fn seed(key: VerifierKey) -> Self {
        Self { key: key.k, degree: 1 }
    }

    pub fn public(delta: Fp2, value: Fp2) -> Self {
        Self { key: delta * value, degree: 1 }
    }

    pub fn ordinary(value: VerifierKey) -> Self {
        Self { key: value.k, degree: 1 }
    }

    pub fn add(self, rhs: Self, delta: Fp2) -> Self {
        self.add_sub(rhs, delta, false)
    }

    pub fn sub(self, rhs: Self, delta: Fp2) -> Self {
        self.add_sub(rhs, delta, true)
    }

    fn add_sub(mut self, mut rhs: Self, delta: Fp2, subtract: bool) -> Self {
        if self.degree < rhs.degree {
            self.key = self.key * fp2_pow(delta, usize::from(rhs.degree - self.degree));
            self.degree = rhs.degree;
        } else if rhs.degree < self.degree {
            rhs.key = rhs.key * fp2_pow(delta, usize::from(self.degree - rhs.degree));
        }
        self.key = if subtract { self.key - rhs.key } else { self.key + rhs.key };
        self
    }

    pub fn scale(mut self, scalar: Fp2) -> Self {
        self.key = self.key * scalar;
        self
    }

    pub fn multiply(self, rhs: Self) -> Result<Self, &'static str> {
        let degree = usize::from(self.degree)
            .checked_add(usize::from(rhs.degree))
            .ok_or("C4.1 verifier degree overflow")?;
        if degree > C41_MAX_DEGREE {
            return Err("C4.1 typed verifier product exceeds degree 12");
        }
        Ok(Self { key: self.key * rhs.key, degree: degree as u8 })
    }

    pub fn xor(self, rhs: Self, delta: Fp2) -> Result<Self, &'static str> {
        Ok(self.add(rhs, delta).sub(self.multiply(rhs)?.scale(Fp2::from_base(Fp::new(2))), delta))
    }
}

fn fp2_pow(mut base: Fp2, mut exponent: usize) -> Fp2 {
    let mut result = Fp2::ONE;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn maj7_prover(inputs: &[C41HdProver; 7]) -> Result<C41HdProver, &'static str> {
    let sum = inputs.iter().skip(1).fold(inputs[0], |acc, input| acc.add(*input));
    let mut output = C41HdProver::public(Fp2::from_base(Fp::new(MAJ7_COEFFICIENTS[7])));
    for coefficient in MAJ7_COEFFICIENTS[..7].iter().rev() {
        output =
            output.multiply(sum)?.add(C41HdProver::public(Fp2::from_base(Fp::new(*coefficient))));
    }
    Ok(output)
}

fn maj7_verifier(inputs: &[C41HdVerifier; 7], delta: Fp2) -> Result<C41HdVerifier, &'static str> {
    let sum = inputs.iter().skip(1).fold(inputs[0], |acc, input| acc.add(*input, delta));
    let mut output = C41HdVerifier::public(delta, Fp2::from_base(Fp::new(MAJ7_COEFFICIENTS[7])));
    for coefficient in MAJ7_COEFFICIENTS[..7].iter().rev() {
        output = output
            .multiply(sum)?
            .add(C41HdVerifier::public(delta, Fp2::from_base(Fp::new(*coefficient))), delta);
    }
    Ok(output)
}

pub fn c41_xor4_maj7_prover(
    seed: &[ProverSubAuthed],
    sigma: [usize; 11],
) -> Result<C41HdProver, &'static str> {
    if seed.len() != C41_SEED_BITS
        || sigma.iter().any(|&index| index >= seed.len())
        || (1..sigma.len()).any(|index| sigma[..index].contains(&sigma[index]))
    {
        return Err("invalid C4.1 XOR4-MAJ7 seed or incidence row");
    }
    let inputs = sigma.map(|index| C41HdProver::seed(seed[index]));
    let majority: [C41HdProver; 7] = inputs[4..].try_into().expect("fixed XOR4-MAJ7 arity");
    inputs[0].xor(inputs[1])?.xor(inputs[2])?.xor(inputs[3])?.xor(maj7_prover(&majority)?)
}

pub fn c41_xor4_maj7_verifier(
    delta: Fp2,
    seed: &[VerifierKey],
    sigma: [usize; 11],
) -> Result<C41HdVerifier, &'static str> {
    if seed.len() != C41_SEED_BITS
        || sigma.iter().any(|&index| index >= seed.len())
        || (1..sigma.len()).any(|index| sigma[..index].contains(&sigma[index]))
    {
        return Err("invalid C4.1 XOR4-MAJ7 verifier seed or incidence row");
    }
    let inputs = sigma.map(|index| C41HdVerifier::seed(seed[index]));
    let majority: [C41HdVerifier; 7] = inputs[4..].try_into().expect("fixed XOR4-MAJ7 arity");
    inputs[0]
        .xor(inputs[1], delta)?
        .xor(inputs[2], delta)?
        .xor(inputs[3], delta)?
        .xor(maj7_verifier(&majority, delta)?, delta)
}

/// Eleven distinct public seed indices for one PRG output.  Assigning one
/// ChaCha stream per output makes incidence generation embarrassingly
/// parallel while remaining bit-exact between the CPU oracle and CUDA.
pub fn c41_public_sigma(
    public_seed: [u8; 32],
    expansion: usize,
    output: usize,
) -> Result<[usize; 11], &'static str> {
    if output >= C41_PRG_OUTPUT_BITS || expansion > u32::MAX as usize {
        return Err("C4.1 public incidence coordinate is out of range");
    }
    let domain = (u64::try_from(expansion).expect("bounded expansion") << 20)
        | u64::try_from(output).expect("bounded output");
    let mut stream = FpStream::domain_separated(public_seed, domain);
    let mut sigma = [0usize; 11];
    for index in 0..sigma.len() {
        loop {
            let candidate = stream.next_bits(10) as usize;
            if !sigma[..index].contains(&candidate) {
                sigma[index] = candidate;
                break;
            }
        }
    }
    Ok(sigma)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41SetupProverLot {
    pub cells: usize,
    pub a: Vec<Fp2>,
    pub b: Vec<Fp2>,
    pub a_values: Vec<u16>,
    pub b_bitmap: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41SetupVerifierLot {
    pub a_keys: Vec<Fp2>,
    pub b_keys: Vec<Fp2>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41TypedSetupProverState {
    pub bits: Vec<u8>,
    pub tags: Vec<Fp2>,
    pub rows: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41TypedSetupVerifierState {
    pub keys: Vec<Fp2>,
    pub rows: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41TypedSetupProof {
    pub rows: u16,
    pub corrections: Vec<u64>,
    pub bitness_close: C41DegreeCloseProof,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct C41TypedSetupMetrics {
    pub prover_to_verifier_bytes: u64,
    pub verifier_to_prover_bytes: u64,
    pub total_typed_setup_bytes: u64,
    pub subfield_correlations: u64,
    pub full_field_correlations: u64,
    pub conditional_soundness_bits: f64,
    pub conditional_weight_zk_bits: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct C41TypedSetupExchange {
    pub proof: C41TypedSetupProof,
    pub prover: C41TypedSetupProverState,
    pub verifier: C41TypedSetupVerifierState,
    pub metrics: C41TypedSetupMetrics,
}

fn c41_seed_bits(secret_entropy: [u8; 32], domain: u64, count: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c41/xor4-maj7/seed-bits/v1");
    hasher.update(&secret_entropy);
    hasher.update(&domain.to_le_bytes());
    let mut packed = vec![0u8; count.div_ceil(8)];
    hasher.finalize_xof().fill(&mut packed);
    (0..count).map(|index| (packed[index / 8] >> (index % 8)) & 1).collect()
}

/// Execute the malicious two-party seed setup in the repository's current
/// interactive simulation. The returned states are party-separated; only
/// the canonical proof crosses from prover to verifier.
#[allow(clippy::too_many_arguments)]
pub fn c41_typed_setup_exchange(
    secret_entropy: [u8; 32],
    public_incidence_seed: [u8; 32],
    rows: usize,
    seed_domain_base: u64,
    bitness_mask_domain: u64,
    prover_stream: &mut CorrelationStream,
    verifier_ctx: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
) -> Result<C41TypedSetupExchange, &'static str> {
    if secret_entropy == [0; 32]
        || public_incidence_seed == [0; 32]
        || rows == 0
        || rows > u16::MAX as usize
        || seed_domain_base.checked_add(rows as u64).is_none_or(|end| end >= bitness_mask_domain)
    {
        return Err("invalid C4.1 typed setup identity or domain range");
    }
    let count = rows.checked_mul(C41_SEED_BITS).ok_or("C4.1 typed seed count overflow")?;
    let bits = c41_seed_bits(secret_entropy, seed_domain_base, count);
    prover_tx.append_message("c41_incidence_seed", &public_incidence_seed);
    verifier_tx.append_message("c41_incidence_seed", &public_incidence_seed);
    let mut corrections = Vec::with_capacity(count);
    let mut authenticated = Vec::with_capacity(count);
    let mut verifier_keys = Vec::with_capacity(count);
    for row in 0..rows {
        let domain = seed_domain_base + row as u64;
        let values = bits[row * C41_SEED_BITS..(row + 1) * C41_SEED_BITS]
            .iter()
            .map(|bit| i16::from(*bit))
            .collect::<Vec<_>>();
        let (row_corrections, row_authenticated) =
            auth_prover(prover_stream, domain, &values, prover_tx);
        verifier_tx.append("auth_corrections", (8 * C41_SEED_BITS) as u64);
        verifier_keys.extend(auth_verifier(verifier_ctx, domain, &row_corrections));
        corrections.extend(row_corrections);
        authenticated.extend(row_authenticated);
    }
    // The public incidence seed is the verifier's first move; the bitness
    // challenge is its second. Transcript challenges are interactive in C4.
    let prover_challenge = prover_tx.challenge_fp2();
    let verifier_challenge = verifier_tx.challenge_fp2();
    if prover_challenge != verifier_challenge {
        return Err("C4.1 typed setup transcripts disagree on bitness challenge");
    }
    let prover_relation = c41_batch_relation_prover(
        authenticated.iter().copied().map(c41_bit_relation_prover),
        prover_challenge,
    )?;
    let verifier_relation = c41_batch_relation_verifier(
        verifier_ctx.delta,
        verifier_keys.iter().copied().map(|key| c41_bit_relation_verifier(verifier_ctx.delta, key)),
        verifier_challenge,
    )?;
    let masks = prover_stream.draw_fulls(bitness_mask_domain, 1);
    let mask_keys = verifier_ctx.expand_full_verifier_keys(bitness_mask_domain, 1);
    let bitness_close = c41_degree_close_prover(prover_relation, &masks, prover_tx)?;
    if !c41_degree_close_verify(
        verifier_relation,
        &mask_keys,
        verifier_ctx.delta,
        &bitness_close,
        verifier_tx,
    ) {
        return Err("C4.1 typed seed bitness close rejected");
    }
    let proof = C41TypedSetupProof { rows: rows as u16, corrections, bitness_close };
    let encoded = proof.encode()?;
    if C41TypedSetupProof::decode(&encoded)? != proof {
        return Err("C4.1 typed setup codec roundtrip disagrees");
    }
    let prover = C41TypedSetupProverState {
        bits,
        tags: authenticated.into_iter().map(|value| value.m).collect(),
        rows,
    };
    let verifier = C41TypedSetupVerifierState {
        keys: verifier_keys.into_iter().map(|value| value.k).collect(),
        rows,
    };
    let prover_to_verifier_bytes = encoded.len() as u64;
    let verifier_to_prover_bytes = 32 + 16;
    Ok(C41TypedSetupExchange {
        proof,
        prover,
        verifier,
        metrics: C41TypedSetupMetrics {
            prover_to_verifier_bytes,
            verifier_to_prover_bytes,
            total_typed_setup_bytes: prover_to_verifier_bytes + verifier_to_prover_bytes,
            subfield_correlations: count as u64,
            full_field_correlations: 1,
            conditional_soundness_bits: 78.809_294_873_915_72,
            conditional_weight_zk_bits: 128.0 - (rows as f64).log2(),
        },
    })
}

impl C41TypedSetupProof {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let rows = usize::from(self.rows);
        if rows == 0
            || self.corrections.len() != rows.saturating_mul(C41_SEED_BITS)
            || self.bitness_close.degree != 2
            || self.bitness_close.coefficients.len() != 2
        {
            return Err("invalid C4.1 typed setup proof geometry");
        }
        let capacity = C41_SETUP_MAGIC.len()
            + 4
            + rows * (C41_SETUP_ROW_HEADER_BYTES + 8 * C41_SEED_BITS)
            + 9
            + 32;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(C41_SETUP_MAGIC);
        bytes.extend_from_slice(&C41_SETUP_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.rows.to_le_bytes());
        for row in 0..rows {
            bytes.extend_from_slice(&[0xC4, 1, 0]);
            bytes.extend_from_slice(&(row as u32).to_le_bytes());
            bytes.extend_from_slice(&(C41_SEED_BITS as u16).to_le_bytes());
            for correction in &self.corrections[row * C41_SEED_BITS..(row + 1) * C41_SEED_BITS] {
                if *correction >= P {
                    return Err("noncanonical C4.1 typed seed correction");
                }
                bytes.extend_from_slice(&correction.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.bitness_close.encode_framed()?);
        debug_assert_eq!(bytes.len(), capacity);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 || &bytes[..8] != C41_SETUP_MAGIC {
            return Err("invalid C4.1 typed setup proof prefix");
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
        let rows = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed row count"));
        if version != C41_SETUP_VERSION || rows == 0 {
            return Err("unsupported C4.1 typed setup proof version or row count");
        }
        let expected = 12usize
            .checked_add(
                usize::from(rows)
                    .checked_mul(C41_SETUP_ROW_HEADER_BYTES + 8 * C41_SEED_BITS)
                    .ok_or("C4.1 typed setup proof length overflow")?,
            )
            .and_then(|length| length.checked_add(9 + 32))
            .ok_or("C4.1 typed setup proof length overflow")?;
        if bytes.len() != expected {
            return Err("truncated or trailing C4.1 typed setup proof bytes");
        }
        let mut offset = 12;
        let mut corrections = Vec::with_capacity(usize::from(rows) * C41_SEED_BITS);
        for row in 0..usize::from(rows) {
            let header = &bytes[offset..offset + C41_SETUP_ROW_HEADER_BYTES];
            if header[..3] != [0xC4, 1, 0]
                || u32::from_le_bytes(header[3..7].try_into().expect("fixed row")) != row as u32
                || u16::from_le_bytes(header[7..9].try_into().expect("fixed count"))
                    != C41_SEED_BITS as u16
            {
                return Err("noncanonical C4.1 typed setup row header");
            }
            offset += C41_SETUP_ROW_HEADER_BYTES;
            for encoded in bytes[offset..offset + 8 * C41_SEED_BITS].chunks_exact(8) {
                let correction = u64::from_le_bytes(encoded.try_into().expect("fixed correction"));
                if correction >= P {
                    return Err("noncanonical C4.1 typed seed correction");
                }
                corrections.push(correction);
            }
            offset += 8 * C41_SEED_BITS;
        }
        let bitness_close = C41DegreeCloseProof::decode_framed(&bytes[offset..])?;
        let proof = Self { rows, corrections, bitness_close };
        if proof.encode()?.as_slice() != bytes {
            return Err("noncanonical C4.1 typed setup proof encoding");
        }
        Ok(proof)
    }
}

fn c41_output_coordinate(global_bit: usize) -> (usize, usize) {
    let expansion = global_bit / C41_PRG_USABLE_BITS;
    let output = C41_SEED_BITS + global_bit % C41_PRG_USABLE_BITS;
    (expansion, output)
}

/// CPU correctness oracle for setup. Production-size lots are generated by
/// the CUDA path; this deliberately simple implementation is used only for
/// small differentials.
pub fn c41_expand_packed_cells_reference(
    public_seed: [u8; 32],
    seed_rows: &[Vec<ProverSubAuthed>],
    first_global_bit: usize,
    cells: usize,
) -> Result<C41SetupProverLot, &'static str> {
    let bit_count =
        cells.checked_mul(C41_BITS_PER_PACKED_CELL).ok_or("C4.1 packed-cell bit count overflow")?;
    let end = first_global_bit.checked_add(bit_count).ok_or("C4.1 global bit range overflow")?;
    if cells == 0
        || seed_rows.iter().any(|row| row.len() != C41_SEED_BITS)
        || end > seed_rows.len().saturating_mul(C41_PRG_USABLE_BITS)
    {
        return Err("invalid C4.1 prover setup geometry");
    }
    let mut lot = C41SetupProverLot {
        cells,
        a: vec![Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES * cells],
        b: vec![Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES * cells],
        a_values: vec![0; cells],
        b_bitmap: vec![0; cells.div_ceil(8)],
    };
    for cell in 0..cells {
        let bit_base = first_global_bit + C41_BITS_PER_PACKED_CELL * cell;
        let mut packed = C41HdProver {
            coefficients: [Fp2::ZERO; C41_MAX_DEGREE + 1],
            degree: C41_MAX_DEGREE as u8,
        };
        for bit in 0..C41_BITS_PER_PACKED_CELL {
            let (expansion, output) = c41_output_coordinate(bit_base + bit);
            let sigma = c41_public_sigma(public_seed, expansion, output)?;
            let value = c41_xor4_maj7_prover(&seed_rows[expansion], sigma)?;
            if bit < 16 {
                packed = packed.add(value.scale(Fp2::from_base(Fp::new(1u64 << bit))));
            } else {
                for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
                    lot.b[lane * cells + cell] = value.coefficients[lane];
                }
                if value.value() == Fp2::ONE {
                    lot.b_bitmap[cell / 8] |= 1 << (cell % 8);
                }
            }
        }
        if packed.value().c1 != Fp::ZERO {
            return Err("C4.1 packed setup value escaped the base field");
        }
        lot.a_values[cell] = u16::try_from(packed.value().c0.value())
            .map_err(|_| "C4.1 packed setup value exceeds u16")?;
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
            lot.a[lane * cells + cell] = packed.coefficients[lane];
        }
    }
    Ok(lot)
}

pub fn c41_expand_packed_keys_reference(
    public_seed: [u8; 32],
    delta: Fp2,
    seed_rows: &[Vec<VerifierKey>],
    first_global_bit: usize,
    cells: usize,
) -> Result<C41SetupVerifierLot, &'static str> {
    let bit_count = cells
        .checked_mul(C41_BITS_PER_PACKED_CELL)
        .ok_or("C4.1 verifier packed-cell bit count overflow")?;
    let end =
        first_global_bit.checked_add(bit_count).ok_or("C4.1 verifier global bit range overflow")?;
    if cells == 0
        || seed_rows.iter().any(|row| row.len() != C41_SEED_BITS)
        || end > seed_rows.len().saturating_mul(C41_PRG_USABLE_BITS)
    {
        return Err("invalid C4.1 verifier setup geometry");
    }
    let mut lot =
        C41SetupVerifierLot { a_keys: vec![Fp2::ZERO; cells], b_keys: vec![Fp2::ZERO; cells] };
    for cell in 0..cells {
        let bit_base = first_global_bit + C41_BITS_PER_PACKED_CELL * cell;
        let mut packed = C41HdVerifier { key: Fp2::ZERO, degree: C41_MAX_DEGREE as u8 };
        for bit in 0..C41_BITS_PER_PACKED_CELL {
            let (expansion, output) = c41_output_coordinate(bit_base + bit);
            let sigma = c41_public_sigma(public_seed, expansion, output)?;
            let value = c41_xor4_maj7_verifier(delta, &seed_rows[expansion], sigma)?;
            if bit < 16 {
                packed = packed.add(value.scale(Fp2::from_base(Fp::new(1u64 << bit))), delta);
            } else {
                lot.b_keys[cell] = value.key;
            }
        }
        lot.a_keys[cell] = packed.key;
    }
    Ok(lot)
}

fn c41_expand_packed_key_at(
    public_seed: [u8; 32],
    delta: Fp2,
    seed_keys: &[VerifierKey],
    rows: usize,
    first_global_bit: usize,
) -> Result<(Fp2, Fp2), &'static str> {
    if rows == 0 || seed_keys.len() != rows.saturating_mul(C41_SEED_BITS) {
        return Err("invalid C4.1 seed-only verifier inventory");
    }
    let end = first_global_bit
        .checked_add(C41_BITS_PER_PACKED_CELL)
        .ok_or("C4.1 seed-only coordinate overflow")?;
    if end > rows.saturating_mul(C41_PRG_USABLE_BITS) {
        return Err("C4.1 seed-only coordinate escapes its inventory");
    }
    let mut packed = C41HdVerifier { key: Fp2::ZERO, degree: C41_MAX_DEGREE as u8 };
    let mut b_key = Fp2::ZERO;
    for bit in 0..C41_BITS_PER_PACKED_CELL {
        let (expansion, output) = c41_output_coordinate(first_global_bit + bit);
        let row = &seed_keys[expansion * C41_SEED_BITS..(expansion + 1) * C41_SEED_BITS];
        let sigma = c41_public_sigma(public_seed, expansion, output)?;
        let value = c41_xor4_maj7_verifier(delta, row, sigma)?;
        if bit < 16 {
            packed = packed.add(value.scale(Fp2::from_base(Fp::new(1u64 << bit))), delta);
        } else {
            b_key = value.key;
        }
    }
    Ok((packed.key, b_key))
}

/// Materialize the verifier-secret packed keys once during setup. The response
/// verifier then performs only the descriptor/query fold.
pub fn c41_materialize_packed_keys(
    public_seed: [u8; 32],
    delta: Fp2,
    setup: &C41TypedSetupVerifierState,
    first_global_bit: usize,
    cells: usize,
) -> Result<C41SetupVerifierLot, &'static str> {
    let end = cells
        .checked_mul(C41_BITS_PER_PACKED_CELL)
        .and_then(|bits| first_global_bit.checked_add(bits));
    if public_seed == [0; 32]
        || delta == Fp2::ZERO
        || cells == 0
        || setup.rows == 0
        || setup.keys.len() != setup.rows.saturating_mul(C41_SEED_BITS)
        || end.is_none_or(|end| end > setup.rows.saturating_mul(C41_PRG_USABLE_BITS))
    {
        return Err("invalid C41SC1 materialized verifier inventory");
    }
    let seed_keys = setup.keys.iter().copied().map(VerifierKey::new).collect::<Vec<_>>();
    let pairs = (0..cells)
        .into_par_iter()
        .map(|cell| {
            c41_expand_packed_key_at(
                public_seed,
                delta,
                &seed_keys,
                setup.rows,
                first_global_bit + cell * C41_BITS_PER_PACKED_CELL,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut a_keys = Vec::with_capacity(cells);
    let mut b_keys = Vec::with_capacity(cells);
    for (a, b) in pairs {
        a_keys.push(a);
        b_keys.push(b);
    }
    Ok(C41SetupVerifierLot { a_keys, b_keys })
}

/// Full-geometry verifier expansion smoke without a materialized lot or dense
/// query. The all-one fold exercises every seed-derived packed key and leaves
/// only two field accumulators live.
pub fn c41_seed_streaming_checksum(
    setup: &C41TypedSetupVerifierState,
    public_seed: [u8; 32],
    first_global_bit: usize,
    cells: usize,
    delta: Fp2,
    chunk_cells: usize,
) -> Result<(Fp2, Fp2), &'static str> {
    let required = cells
        .checked_mul(C41_BITS_PER_PACKED_CELL)
        .and_then(|bits| first_global_bit.checked_add(bits))
        .ok_or("C4.1 seed-streaming checksum range overflows")?;
    if public_seed == [0; 32]
        || delta == Fp2::ZERO
        || cells == 0
        || chunk_cells == 0
        || setup.rows == 0
        || setup.keys.len() != setup.rows.saturating_mul(C41_SEED_BITS)
        || required > setup.rows.saturating_mul(C41_PRG_USABLE_BITS)
    {
        return Err("invalid C4.1 seed-streaming checksum geometry");
    }
    let keys = setup.keys.iter().copied().map(VerifierKey::new).collect::<Vec<_>>();
    let mut folded = (Fp2::ZERO, Fp2::ZERO);
    for chunk_start in (0..cells).step_by(chunk_cells) {
        let chunk_end = (chunk_start + chunk_cells).min(cells);
        let chunk = (chunk_start..chunk_end)
            .into_par_iter()
            .map(|cell| {
                c41_expand_packed_key_at(
                    public_seed,
                    delta,
                    &keys,
                    setup.rows,
                    first_global_bit + cell * C41_BITS_PER_PACKED_CELL,
                )
            })
            .try_reduce(
                || (Fp2::ZERO, Fp2::ZERO),
                |left, right| Ok((left.0 + right.0, left.1 + right.1)),
            )?;
        folded.0 += chunk.0;
        folded.1 += chunk.1;
    }
    Ok(folded)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41PackedCorrections {
    pub d: Vec<u16>,
    pub e: Vec<u8>,
}

pub fn c41_pack_corrections(
    values: &[i16],
    a_values: &[u16],
    b_bitmap: &[u8],
) -> Result<C41PackedCorrections, &'static str> {
    let cells = values.len();
    if cells == 0 || a_values.len() != cells || b_bitmap.len() != cells.div_ceil(8) {
        return Err("invalid C4.1 Packed16 correction geometry");
    }
    if cells % 8 != 0 && b_bitmap[cells / 8] >> (cells % 8) != 0 {
        return Err("noncanonical C4.1 setup bit tail");
    }
    let mut d = Vec::with_capacity(cells);
    let mut e = vec![0u8; cells.div_ceil(8)];
    for (cell, (&value, &mask)) in values.iter().zip(a_values).enumerate() {
        let shifted = u32::try_from(i32::from(value) + (1 << 15)).expect("i16 shift is u16");
        let correction = shifted.wrapping_sub(u32::from(mask)) as u16;
        let carry = (u32::from(mask) + u32::from(correction) - shifted) >> 16;
        debug_assert!(carry <= 1);
        let setup_bit = (b_bitmap[cell / 8] >> (cell % 8)) & 1;
        let response_bit = setup_bit ^ carry as u8;
        d.push(correction);
        e[cell / 8] |= response_bit << (cell % 8);
    }
    Ok(C41PackedCorrections { d, e })
}

pub fn c41_unpack_corrections(
    setup: &C41SetupProverLot,
    corrections: &C41PackedCorrections,
) -> Result<Vec<i16>, &'static str> {
    let cells = setup.cells;
    if corrections.d.len() != cells
        || corrections.e.len() != cells.div_ceil(8)
        || (cells % 8 != 0 && corrections.e[cells / 8] >> (cells % 8) != 0)
    {
        return Err("invalid C4.1 Packed16 response geometry or bit tail");
    }
    let mut values = Vec::with_capacity(cells);
    for cell in 0..cells {
        let setup_bit = (setup.b_bitmap[cell / 8] >> (cell % 8)) & 1;
        let response_bit = (corrections.e[cell / 8] >> (cell % 8)) & 1;
        let carry = setup_bit ^ response_bit;
        let shifted = i64::from(setup.a_values[cell]) + i64::from(corrections.d[cell])
            - (i64::from(carry) << 16);
        let value = shifted - (1 << 15);
        values.push(i16::try_from(value).map_err(|_| "C4.1 Packed16 value is outside i16")?);
    }
    Ok(values)
}

pub fn c41_bit_relation_prover(bit: ProverSubAuthed) -> C41HdProver {
    let value = C41HdProver::seed(bit);
    value
        .multiply(value.sub(C41HdProver::public(Fp2::ONE)))
        .expect("degree-one bit relation is degree two")
}

pub fn c41_bit_relation_verifier(delta: Fp2, bit: VerifierKey) -> C41HdVerifier {
    let value = C41HdVerifier::seed(bit);
    value
        .multiply(value.sub(C41HdVerifier::public(delta, Fp2::ONE), delta))
        .expect("degree-one verifier bit relation is degree two")
}

pub fn c41_batch_relation_prover(
    relations: impl IntoIterator<Item = C41HdProver>,
    challenge: Fp2,
) -> Result<C41HdProver, &'static str> {
    let mut state = C41HdProver::public(Fp2::ZERO);
    let mut count = 0usize;
    for relation in relations {
        state = state.add(relation).scale(challenge);
        count += 1;
    }
    (count != 0).then_some(state).ok_or("empty C4.1 relation batch")
}

pub fn c41_batch_relation_verifier(
    delta: Fp2,
    relations: impl IntoIterator<Item = C41HdVerifier>,
    challenge: Fp2,
) -> Result<C41HdVerifier, &'static str> {
    let mut state = C41HdVerifier::public(delta, Fp2::ZERO);
    let mut count = 0usize;
    for relation in relations {
        state = state.add(relation, delta).scale(challenge);
        count += 1;
    }
    (count != 0).then_some(state).ok_or("empty C4.1 verifier relation batch")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41DegreeCloseProof {
    pub degree: u8,
    pub coefficients: Vec<Fp2>,
}

pub fn c41_degree_close_prover(
    relation: C41HdProver,
    masks: &[FullCorr],
    tx: &mut Transcript,
) -> Result<C41DegreeCloseProof, &'static str> {
    let degree = usize::from(relation.degree);
    if !(2..=C41_MAX_DEGREE).contains(&degree)
        || masks.len() != degree - 1
        || relation.value() != Fp2::ZERO
    {
        return Err("invalid C4.1 zero relation or close mask census");
    }
    let mut coefficients = relation.coefficients[..degree].to_vec();
    for (index, mask) in masks.iter().enumerate() {
        coefficients[index] += mask.m;
        coefficients[index + 1] += mask.x;
    }
    tx.append_fp2s("c41_degree_close", &coefficients);
    Ok(C41DegreeCloseProof { degree: relation.degree, coefficients })
}

pub fn c41_degree_close_verify(
    relation: C41HdVerifier,
    mask_keys: &[VerifierKey],
    delta: Fp2,
    proof: &C41DegreeCloseProof,
    tx: &mut Transcript,
) -> bool {
    let degree = usize::from(relation.degree);
    if proof.degree != relation.degree
        || !(2..=C41_MAX_DEGREE).contains(&degree)
        || proof.coefficients.len() != degree
        || mask_keys.len() != degree - 1
    {
        return false;
    }
    tx.append_fp2s("c41_degree_close", &proof.coefficients);
    let opened = proof
        .coefficients
        .iter()
        .rev()
        .fold(Fp2::ZERO, |acc, coefficient| acc * delta + *coefficient);
    let mut mask = Fp2::ZERO;
    let mut power = Fp2::ONE;
    for key in mask_keys {
        mask += power * key.k;
        power = power * delta;
    }
    opened == relation.key + mask
}

impl C41DegreeCloseProof {
    pub fn encode_framed(&self) -> Result<Vec<u8>, &'static str> {
        let degree = usize::from(self.degree);
        let magic = match self.degree {
            2 => C41_BITNESS_CLOSE_MAGIC,
            12 => C41_CLOSE_MAGIC,
            _ => return Err("unsupported C4.1 close-frame degree"),
        };
        if self.coefficients.len() != degree {
            return Err("C4.1 close coefficient count differs from degree");
        }
        let mut bytes = Vec::with_capacity(9 + 16 * degree);
        bytes.extend_from_slice(magic);
        bytes.push(self.degree);
        for coefficient in &self.coefficients {
            bytes.extend_from_slice(&coefficient.c0.value().to_le_bytes());
            bytes.extend_from_slice(&coefficient.c1.value().to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn decode_framed(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 9 {
            return Err("truncated C4.1 close frame");
        }
        let degree = bytes[8];
        let expected_magic = match degree {
            2 => C41_BITNESS_CLOSE_MAGIC,
            12 => C41_CLOSE_MAGIC,
            _ => return Err("unsupported C4.1 close-frame degree"),
        };
        if &bytes[..8] != expected_magic || bytes.len() != 9 + 16 * usize::from(degree) {
            return Err("invalid C4.1 close frame geometry");
        }
        let mut coefficients = Vec::with_capacity(usize::from(degree));
        for encoded in bytes[9..].chunks_exact(16) {
            let c0 = u64::from_le_bytes(encoded[..8].try_into().expect("fixed limb"));
            let c1 = u64::from_le_bytes(encoded[8..].try_into().expect("fixed limb"));
            if c0 >= P || c1 >= P {
                return Err("noncanonical C4.1 close field element");
            }
            coefficients.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
        }
        let proof = Self { degree, coefficients };
        if proof.encode_framed()?.as_slice() != bytes {
            return Err("noncanonical C4.1 close encoding");
        }
        Ok(proof)
    }

    pub fn encode_degree12(&self) -> Result<Vec<u8>, &'static str> {
        if self.degree != 12 || self.coefficients.len() != 12 {
            return Err("C4.1 response close must have degree 12");
        }
        let bytes = self.encode_framed()?;
        debug_assert_eq!(bytes.len(), C41_DEGREE12_CLOSE_BYTES);
        Ok(bytes)
    }

    pub fn decode_degree12(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != C41_DEGREE12_CLOSE_BYTES {
            return Err("invalid C4.1 degree-12 close frame");
        }
        Self::decode_framed(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41FoldedQueries {
    pub a: [Fp2; C41_TYPED_POLYNOMIAL_LANES],
    pub b: [Fp2; C41_TYPED_POLYNOMIAL_LANES],
}

/// Reference for the two folded queries, with coefficient-major setup slabs.
pub fn c41_fold_typed_queries_reference(
    a: &[Fp2],
    b: &[Fp2],
    query: &[Fp2],
    correction_bitmap: &[u8],
) -> Result<C41FoldedQueries, &'static str> {
    let cells = query.len();
    let bitmap_bytes = cells.checked_add(7).ok_or("C4.1 cell count overflow")? / 8;
    let slab_len =
        C41_TYPED_POLYNOMIAL_LANES.checked_mul(cells).ok_or("C4.1 slab length overflow")?;
    if cells == 0
        || correction_bitmap.len() != bitmap_bytes
        || a.len() != slab_len
        || b.len() != a.len()
        || (cells % 8 != 0 && correction_bitmap[bitmap_bytes - 1] >> (cells % 8) != 0)
    {
        return Err("invalid C4.1 folded-query geometry or correction bit");
    }
    let mut folded = C41FoldedQueries {
        a: [Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES],
        b: [Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES],
    };
    for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
        for cell in 0..cells {
            let weight = query[cell];
            folded.a[lane] += weight * a[lane * cells + cell];
            let signed_weight = if (correction_bitmap[cell / 8] >> (cell % 8)) & 1 == 0 {
                weight
            } else {
                Fp2::ZERO - weight
            };
            folded.b[lane] += signed_weight * b[lane * cells + cell];
        }
    }
    Ok(folded)
}

/// Resident prover path. Output layout is the 12 `a` coefficients followed by
/// the 12 `(1-2e)b` coefficients and stays on device for the degree-12 close.
pub fn c41_fold_typed_queries_resident(
    backend: &mut Backend,
    a: &DeviceBuffer<Fp2Repr>,
    b: &DeviceBuffer<Fp2Repr>,
    query: &DeviceBuffer<Fp2Repr>,
    correction_bitmap: &DeviceBuffer<u8>,
    cells: usize,
) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
    backend.c41_fold_typed_queries_device(a, b, query, correction_bitmap, cells)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41ResponseProof {
    pub d: Vec<u16>,
    pub e: Vec<u8>,
    pub bridge_corrections: Vec<Fp2>,
    pub close: C41DegreeCloseProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C41ResponseSegment {
    offset: usize,
    rows: usize,
    cols: usize,
}

struct C41ProverBridge {
    entries: Vec<(usize, Fp2)>,
    ordinary: ProverAuthed,
}

struct C41VerifierBridge {
    query: C41VerifierQuery,
    ordinary: VerifierKey,
}

enum C41VerifierQuery {
    Matrix {
        segment: C41ResponseSegment,
        row_weights: Arc<[Fp2]>,
        column_weights: Arc<[Fp2]>,
    },
    CacheColumns {
        segment: C41ResponseSegment,
        row: usize,
        column_offset: usize,
        weights: Arc<[Fp2]>,
    },
    CacheRows {
        segments: Arc<[C41ResponseSegment]>,
        weights: Arc<[Fp2]>,
        column_offset: usize,
        column: usize,
    },
    CacheMatrix {
        segments: Arc<[C41ResponseSegment]>,
        row_weights: Arc<[Fp2]>,
        column_weights: Arc<[Fp2]>,
        column_offset: usize,
    },
}

impl C41VerifierQuery {
    fn add_to_chunk(&self, chunk_start: usize, chunk: &mut [Fp2], scale: Fp2) {
        let chunk_end = chunk_start + chunk.len();
        let mut add = |cell: usize, coefficient: Fp2| {
            if (chunk_start..chunk_end).contains(&cell) {
                chunk[cell - chunk_start] += scale * coefficient;
            }
        };
        match self {
            Self::Matrix { segment, row_weights, column_weights } => {
                let start = chunk_start.max(segment.offset);
                let end = chunk_end.min(segment.offset + segment.rows * segment.cols);
                for cell in start..end {
                    let local = cell - segment.offset;
                    add(
                        cell,
                        row_weights[local / segment.cols] * column_weights[local % segment.cols],
                    );
                }
            }
            Self::CacheColumns { segment, row, column_offset, weights } => {
                let base = segment.offset + row * segment.cols + column_offset;
                let start = chunk_start.max(base);
                let end = chunk_end.min(base + weights.len());
                for cell in start..end {
                    add(cell, weights[cell - base]);
                }
            }
            Self::CacheRows { segments, weights, column_offset, column } => {
                let mut weight_offset = 0;
                for segment in segments.iter() {
                    let base = segment.offset + column_offset + column;
                    let start_row = chunk_start.saturating_sub(base).div_ceil(segment.cols);
                    let end_row = chunk_end.saturating_sub(base).div_ceil(segment.cols);
                    for row in start_row.min(segment.rows)..end_row.min(segment.rows) {
                        add(base + row * segment.cols, weights[weight_offset + row]);
                    }
                    weight_offset += segment.rows;
                }
            }
            Self::CacheMatrix { segments, row_weights, column_weights, column_offset } => {
                let mut row_offset = 0;
                for segment in segments.iter() {
                    let first = segment.offset + column_offset;
                    let start_row = chunk_start
                        .saturating_sub(first + column_weights.len().saturating_sub(1))
                        .div_ceil(segment.cols);
                    let end_row = chunk_end.saturating_sub(first).div_ceil(segment.cols);
                    for row in start_row.min(segment.rows)..end_row.min(segment.rows) {
                        let base = segment.offset + row * segment.cols + column_offset;
                        let start = chunk_start.max(base);
                        let end = chunk_end.min(base + column_weights.len());
                        for cell in start..end {
                            add(cell, row_weights[row_offset + row] * column_weights[cell - base]);
                        }
                    }
                    row_offset += segment.rows;
                }
            }
        }
    }
}

fn packed_bits(values: &[u8]) -> Vec<u8> {
    let mut packed = vec![0u8; values.len().div_ceil(8)];
    for (index, value) in values.iter().copied().enumerate() {
        packed[index / 8] |= value << (index % 8);
    }
    packed
}

fn exact_bits(len: usize) -> usize {
    usize::BITS as usize - len.saturating_sub(1).leading_zeros() as usize
}

fn matrix_query(rows: usize, cols: usize, point: &[Fp2]) -> Result<Vec<Fp2>, AccelError> {
    let col_bits = exact_bits(cols);
    if point.len() != col_bits + exact_bits(rows) {
        return Err(AccelError::InvalidInput("C4.1 matrix query point mismatch"));
    }
    let columns = crate::mle::eq_vec(&point[..col_bits]);
    let row_weights = crate::mle::eq_vec(&point[col_bits..]);
    let mut query = Vec::with_capacity(rows * cols);
    for row_weight in row_weights.into_iter().take(rows) {
        query.extend(columns.iter().take(cols).map(|column| row_weight * *column));
    }
    Ok(query)
}

pub struct C41ProverResponseState {
    lot: Option<C41PackedProverDeviceLot>,
    a_values: Vec<u16>,
    b_values: Vec<u8>,
    d: Vec<u16>,
    e_values: Vec<u8>,
    segments: BTreeMap<u64, C41ResponseSegment>,
    cursor: usize,
    bridge_corrections: Vec<Fp2>,
    bridges: Vec<C41ProverBridge>,
    diagnostics_handle: Option<Arc<Mutex<C41ProverDiagnostics>>>,
    diagnostics: C41ProverDiagnostics,
}

impl C41ProverResponseState {
    pub fn new(lot: C41PackedProverDeviceLot, backend: &mut Backend) -> Result<Self, AccelError> {
        Self::new_inner(lot, backend, None)
    }

    pub fn new_with_diagnostics(
        lot: C41PackedProverDeviceLot,
        backend: &mut Backend,
        diagnostics: Arc<Mutex<C41ProverDiagnostics>>,
    ) -> Result<Self, AccelError> {
        Self::new_inner(lot, backend, Some(diagnostics))
    }

    fn new_inner(
        lot: C41PackedProverDeviceLot,
        backend: &mut Backend,
        diagnostics_handle: Option<Arc<Mutex<C41ProverDiagnostics>>>,
    ) -> Result<Self, AccelError> {
        let cells = lot.cells;
        let started = diagnostics_handle.as_ref().map(|_| Instant::now());
        let a_values = backend.download_device(&lot.a_values, 0, cells)?;
        let b_values = backend.download_device(&lot.b_values, 0, cells)?;
        if b_values.iter().any(|value| *value > 1) {
            return Err(AccelError::InvalidInput("C4.1 lot contains a non-bit mask"));
        }
        let mut diagnostics = C41ProverDiagnostics { cells, ..C41ProverDiagnostics::default() };
        if let Some(started) = started {
            diagnostics.lot_prepare_download_s = started.elapsed().as_secs_f64();
        }
        Ok(Self {
            lot: Some(lot),
            a_values,
            b_values,
            d: vec![0; cells],
            e_values: vec![0; cells],
            segments: BTreeMap::new(),
            cursor: 0,
            bridge_corrections: Vec::new(),
            bridges: Vec::new(),
            diagnostics_handle,
            diagnostics,
        })
    }

    pub fn cells(&self) -> usize {
        self.a_values.len()
    }

    pub fn has_domain(&self, domain: u64) -> bool {
        self.segments.contains_key(&domain)
    }

    pub fn register_resident_matrix(
        &mut self,
        domain: u64,
        values: DeviceSlice<'_, i16>,
        rows: usize,
        cols: usize,
        tx: &mut Transcript,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        let started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let cells = rows
            .checked_mul(cols)
            .ok_or(AccelError::InvalidInput("C4.1 response segment overflows"))?;
        let end = self
            .cursor
            .checked_add(cells)
            .filter(|end| *end <= self.cells())
            .ok_or(AccelError::InvalidInput("C4.1 response lot is exhausted"))?;
        if values.len() < cells || self.segments.contains_key(&domain) {
            return Err(AccelError::InvalidInput("invalid C4.1 response segment"));
        }
        let plaintexts = backend.download_device(values.buffer(), values.offset(), cells)?;
        for (local, value) in plaintexts.into_iter().enumerate() {
            let cell = self.cursor + local;
            let shifted =
                u32::try_from(i32::from(value) + (1 << 15)).expect("i16 shift is nonnegative");
            let correction = shifted.wrapping_sub(u32::from(self.a_values[cell])) as u16;
            let carry = (u32::from(self.a_values[cell]) + u32::from(correction) - shifted) >> 16;
            self.d[cell] = correction;
            self.e_values[cell] = self.b_values[cell] ^ carry as u8;
        }
        let mut d_bytes = Vec::with_capacity(2 * cells);
        for value in &self.d[self.cursor..end] {
            d_bytes.extend_from_slice(&value.to_le_bytes());
        }
        tx.append_message(C41_PACKED_D_LABEL, &d_bytes);
        tx.append_message(C41_PACKED_E_LABEL, &packed_bits(&self.e_values[self.cursor..end]));
        self.segments.insert(domain, C41ResponseSegment { offset: self.cursor, rows, cols });
        self.cursor = end;
        if let Some(started) = started {
            self.diagnostics.registration_s += started.elapsed().as_secs_f64();
            self.diagnostics.segments += 1;
        }
        Ok(())
    }

    fn bridge_entries(
        &mut self,
        entries: impl IntoIterator<Item = (usize, Fp2)>,
        value: Fp2,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
    ) -> Result<ProverAuthed, AccelError> {
        let started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let entries = entries.into_iter().collect::<Vec<_>>();
        if entries.is_empty() || entries.iter().any(|(cell, _)| *cell >= self.cells()) {
            return Err(AccelError::InvalidInput("C4.1 bridge query escapes its lot"));
        }
        let index = self.bridge_corrections.len();
        if index >= C41_MAX_BRIDGES_PER_RESPONSE {
            return Err(AccelError::InvalidInput("C4.1 bridge count exceeds soundness cap"));
        }
        let domain = C41_BRIDGE_DOMAIN_BASE
            .checked_add(index as u64)
            .ok_or(AccelError::InvalidInput("C4.1 bridge domain overflows"))?;
        let correlation = stream.draw_fulls(domain, 1)[0];
        stream
            .record_c6_fullfield_plaintexts(domain, &[value])
            .map_err(|_| AccelError::InvalidInput("C4.1 bridge correlation schedule differs"))?;
        let correction = value - correlation.x;
        tx.append_fp2s(C41_BRIDGE_LABEL, &[correction]);
        self.bridge_corrections.push(correction);
        let ordinary = correlation.authenticate(value);
        if let Some(started) = started {
            self.diagnostics.bridge_build_s += started.elapsed().as_secs_f64();
            self.diagnostics.bridges += 1;
            self.diagnostics.bridge_sparse_entries += entries.len() as u64;
        }
        self.bridges.push(C41ProverBridge { entries, ordinary });
        Ok(ordinary)
    }

    pub fn bridge_matrix(
        &mut self,
        domain: u64,
        rows: usize,
        cols: usize,
        point: &[Fp2],
        value: Fp2,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
    ) -> Result<ProverAuthed, AccelError> {
        let segment = *self
            .segments
            .get(&domain)
            .ok_or(AccelError::InvalidInput("unknown C4.1 matrix domain"))?;
        if segment.rows != rows || segment.cols != cols {
            return Err(AccelError::InvalidInput("C4.1 matrix segment geometry differs"));
        }
        let query = matrix_query(rows, cols, point)?;
        self.bridge_entries(
            query.into_iter().enumerate().map(|(index, weight)| (segment.offset + index, weight)),
            value,
            stream,
            tx,
        )
    }

    pub fn bridge_cache_columns(
        &mut self,
        segments: &[(u64, usize)],
        weights: &[Fp2],
        column_offset: usize,
        width: usize,
        values: &[Fp2],
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
    ) -> Result<Vec<ProverAuthed>, AccelError> {
        if values.len() != segments.iter().map(|segment| segment.1).sum::<usize>()
            || weights.len() < width
        {
            return Err(AccelError::InvalidInput("C4.1 cache-column fold geometry differs"));
        }
        let mut output = Vec::with_capacity(values.len());
        let mut value_index = 0;
        for &(domain, rows) in segments {
            let segment = *self
                .segments
                .get(&domain)
                .ok_or(AccelError::InvalidInput("unknown C4.1 cache segment"))?;
            if segment.rows != rows || column_offset + width > segment.cols {
                return Err(AccelError::InvalidInput("C4.1 cache-column segment differs"));
            }
            for row in 0..rows {
                let entries = (0..width).map(|column| {
                    (segment.offset + row * segment.cols + column_offset + column, weights[column])
                });
                output.push(self.bridge_entries(entries, values[value_index], stream, tx)?);
                value_index += 1;
            }
        }
        Ok(output)
    }

    pub fn bridge_cache_rows(
        &mut self,
        segments: &[(u64, usize)],
        weights: &[Fp2],
        column_offset: usize,
        width: usize,
        values: &[Fp2],
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
    ) -> Result<Vec<ProverAuthed>, AccelError> {
        if values.len() != width || weights.len() < segments.iter().map(|segment| segment.1).sum() {
            return Err(AccelError::InvalidInput("C4.1 cache-row fold geometry differs"));
        }
        let mut output = Vec::with_capacity(width);
        for column in 0..width {
            let mut entries = Vec::new();
            let mut weight_offset = 0;
            for &(domain, rows) in segments {
                let segment = *self
                    .segments
                    .get(&domain)
                    .ok_or(AccelError::InvalidInput("unknown C4.1 cache segment"))?;
                if segment.rows != rows || column_offset + width > segment.cols {
                    return Err(AccelError::InvalidInput("C4.1 cache-row segment differs"));
                }
                entries.extend((0..rows).map(|row| {
                    (
                        segment.offset + row * segment.cols + column_offset + column,
                        weights[weight_offset + row],
                    )
                }));
                weight_offset += rows;
            }
            output.push(self.bridge_entries(entries, values[column], stream, tx)?);
        }
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bridge_cache_matrix(
        &mut self,
        segments: &[(u64, usize)],
        row_weights: &[Fp2],
        column_weights: &[Fp2],
        column_offset: usize,
        value: Fp2,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
    ) -> Result<ProverAuthed, AccelError> {
        let rows = segments.iter().map(|segment| segment.1).sum::<usize>();
        if row_weights.len() < rows || column_weights.is_empty() {
            return Err(AccelError::InvalidInput("C4.1 cache matrix weights differ"));
        }
        let mut entries = Vec::with_capacity(rows * column_weights.len());
        let mut row_offset = 0;
        for &(domain, segment_rows) in segments {
            let segment = *self
                .segments
                .get(&domain)
                .ok_or(AccelError::InvalidInput("unknown C4.1 cache matrix segment"))?;
            if segment.rows != segment_rows || column_offset + column_weights.len() > segment.cols {
                return Err(AccelError::InvalidInput("C4.1 cache matrix geometry differs"));
            }
            for row in 0..segment_rows {
                for (column, weight) in column_weights.iter().copied().enumerate() {
                    entries.push((
                        segment.offset + row * segment.cols + column_offset + column,
                        row_weights[row_offset + row] * weight,
                    ));
                }
            }
            row_offset += segment_rows;
        }
        self.bridge_entries(entries, value, stream, tx)
    }

    pub fn finish(
        mut self,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
        backend: &mut Backend,
    ) -> Result<C41ResponseProof, AccelError> {
        if self.cursor != self.cells()
            || self.bridge_corrections.is_empty()
            || self.bridge_corrections.len() > C41_MAX_BRIDGES_PER_RESPONSE
            || self.bridges.len() != self.bridge_corrections.len()
        {
            return Err(AccelError::InvalidInput("incomplete C4.1 response consumption"));
        }
        let e = packed_bits(&self.e_values);
        let bridge_challenge = tx.challenge_c41_bridge_fp2();
        let mut bridge_power = Fp2::ONE;
        let cells = self.cells();
        let query_build_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let mut query_values = vec![Fp2::ZERO; cells];
        let mut ordinary = C41HdProver::public(Fp2::ZERO);
        for bridge in &self.bridges {
            bridge_power = bridge_power * bridge_challenge;
            for &(cell, coefficient) in &bridge.entries {
                query_values[cell] += bridge_power * coefficient;
            }
            ordinary = ordinary.add(C41HdProver::ordinary(bridge.ordinary).scale(bridge_power));
        }
        if let Some(started) = query_build_started {
            self.diagnostics.dense_query_build_s = started.elapsed().as_secs_f64();
            self.diagnostics.dense_query_bytes = (cells * std::mem::size_of::<Fp2>()) as u64;
            self.diagnostics.rayon_query_scratch_upper_bytes = 0;
        }
        let query_raw = query_values.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let upload_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let query = backend.upload_new_device(&query_raw)?;
        if let Some(started) = upload_started {
            self.diagnostics.query_upload_s = started.elapsed().as_secs_f64();
        }
        let bitmap_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let bitmap = backend.upload_new_device(&e)?;
        if let Some(started) = bitmap_started {
            self.diagnostics.bitmap_upload_s = started.elapsed().as_secs_f64();
        }
        let lot = self.lot.as_ref().expect("C4.1 prover lot is live");
        let fold_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let folded = c41_fold_typed_queries_resident(
            backend,
            &lot.a,
            &lot.b,
            &query,
            &bitmap,
            self.cells(),
        )?;
        if let Some(started) = fold_started {
            self.diagnostics.fused_fold_submit_s = started.elapsed().as_secs_f64();
        }
        let download_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let output = backend.download_device(&folded, 0, folded.len())?;
        if let Some(started) = download_started {
            self.diagnostics.fold_download_sync_s = started.elapsed().as_secs_f64();
        }
        backend.free_device(folded)?;
        backend.free_device(query)?;
        backend.free_device(bitmap)?;
        let radix = Fp2::from_base(Fp::new(1 << 16));
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
            coefficients[lane] = Fp2::from(output[lane]) - radix * Fp2::from(output[12 + lane]);
        }
        // The claimed top coefficient is already the batched ordinary opening.
        // The verifier's independently expanded typed key binds that claim to
        // d/e; recomputing all plaintext cells here would only duplicate work.
        coefficients[12] = ordinary.value();
        let typed = C41HdProver { coefficients, degree: 12 };
        let relation = typed.sub(ordinary);
        if relation.value() != Fp2::ZERO {
            return Err(AccelError::InvalidInput("C4.1 folded bridge plaintext differs"));
        }
        let masks = stream.draw_fulls(C41_CLOSE_MASK_DOMAIN, 11);
        tx.append_message("c41_degree_close_frame", &[C41_CLOSE_MAGIC.as_slice(), &[12]].concat());
        let close_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let close =
            c41_degree_close_prover(relation, &masks, tx).map_err(AccelError::InvalidInput)?;
        if let Some(started) = close_started {
            self.diagnostics.degree12_close_s = started.elapsed().as_secs_f64();
        }
        let cleanup_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let lot = self.lot.take().expect("C4.1 prover lot is consumed once");
        backend.free_device(lot.a)?;
        backend.free_device(lot.b)?;
        backend.free_device(lot.a_values)?;
        backend.free_device(lot.b_values)?;
        if let Some(started) = cleanup_started {
            self.diagnostics.cleanup_s = started.elapsed().as_secs_f64();
        }
        if let Some(handle) = &self.diagnostics_handle {
            *handle.lock().expect("C4.1 prover diagnostics mutex poisoned") =
                self.diagnostics.clone();
        }
        Ok(C41ResponseProof { d: self.d, e, bridge_corrections: self.bridge_corrections, close })
    }
}

enum C41VerifierKeySource {
    Materialized {
        lot: Option<C41PackedVerifierDeviceLot>,
        a_keys: Vec<Fp2>,
        b_keys: Vec<Fp2>,
    },
    SeedOnly {
        public_seed: [u8; 32],
        seed_keys: Vec<VerifierKey>,
        rows: usize,
        first_global_bit: usize,
        delta: Fp2,
        chunk_cells: usize,
    },
}

pub struct C41VerifierResponseState {
    key_source: C41VerifierKeySource,
    d: Vec<u16>,
    e: Vec<u8>,
    segments: BTreeMap<u64, C41ResponseSegment>,
    cursor: usize,
    bridge_corrections: Vec<Fp2>,
    bridge_cursor: usize,
    bridges: Vec<C41VerifierBridge>,
    diagnostics_handle: Option<Arc<Mutex<C41VerifierDiagnostics>>>,
    diagnostics: C41VerifierDiagnostics,
}

impl C41VerifierResponseState {
    fn validate_proof_geometry(cells: usize, proof: &C41ResponseProof) -> Result<(), AccelError> {
        if cells == 0
            || proof.d.len() != cells
            || proof.e.len() != cells.div_ceil(8)
            || (cells % 8 != 0 && proof.e[cells / 8] >> (cells % 8) != 0)
            || proof.bridge_corrections.is_empty()
            || proof.bridge_corrections.len() > C41_MAX_BRIDGES_PER_RESPONSE
        {
            return Err(AccelError::InvalidInput("invalid C4.1 response proof geometry"));
        }
        Ok(())
    }

    pub fn new(
        lot: C41PackedVerifierDeviceLot,
        proof: &C41ResponseProof,
        _delta: Fp2,
        backend: &mut Backend,
    ) -> Result<Self, AccelError> {
        let cells = lot.cells;
        Self::validate_proof_geometry(cells, proof)?;
        let a_keys =
            backend.download_device(&lot.a_keys, 0, cells)?.into_iter().map(Fp2::from).collect();
        let b_keys =
            backend.download_device(&lot.b_keys, 0, cells)?.into_iter().map(Fp2::from).collect();
        Ok(Self {
            key_source: C41VerifierKeySource::Materialized { lot: Some(lot), a_keys, b_keys },
            d: proof.d.clone(),
            e: proof.e.clone(),
            segments: BTreeMap::new(),
            cursor: 0,
            bridge_corrections: proof.bridge_corrections.clone(),
            bridge_cursor: 0,
            bridges: Vec::new(),
            diagnostics_handle: None,
            diagnostics: C41VerifierDiagnostics { cells, ..Default::default() },
        })
    }

    pub fn new_materialized(
        setup: C41SetupVerifierLot,
        proof: &C41ResponseProof,
        diagnostics_handle: Option<Arc<Mutex<C41VerifierDiagnostics>>>,
    ) -> Result<Self, AccelError> {
        let cells = setup.a_keys.len();
        Self::validate_proof_geometry(cells, proof)?;
        if setup.b_keys.len() != cells {
            return Err(AccelError::InvalidInput("C41SC1 materialized verifier keys differ"));
        }
        Ok(Self {
            key_source: C41VerifierKeySource::Materialized {
                lot: None,
                a_keys: setup.a_keys,
                b_keys: setup.b_keys,
            },
            d: proof.d.clone(),
            e: proof.e.clone(),
            segments: BTreeMap::new(),
            cursor: 0,
            bridge_corrections: proof.bridge_corrections.clone(),
            bridge_cursor: 0,
            bridges: Vec::new(),
            diagnostics_handle,
            diagnostics: C41VerifierDiagnostics { cells, ..Default::default() },
        })
    }

    pub fn new_seed_streaming(
        setup: C41TypedSetupVerifierState,
        public_seed: [u8; 32],
        first_global_bit: usize,
        cells: usize,
        proof: &C41ResponseProof,
        delta: Fp2,
    ) -> Result<Self, AccelError> {
        Self::new_seed_streaming_inner(
            setup,
            public_seed,
            first_global_bit,
            cells,
            proof,
            delta,
            C41_VERIFIER_STREAM_CHUNK_CELLS,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_seed_streaming_with_diagnostics(
        setup: C41TypedSetupVerifierState,
        public_seed: [u8; 32],
        first_global_bit: usize,
        cells: usize,
        proof: &C41ResponseProof,
        delta: Fp2,
        diagnostics: Arc<Mutex<C41VerifierDiagnostics>>,
    ) -> Result<Self, AccelError> {
        Self::new_seed_streaming_inner(
            setup,
            public_seed,
            first_global_bit,
            cells,
            proof,
            delta,
            C41_VERIFIER_STREAM_CHUNK_CELLS,
            Some(diagnostics),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_seed_streaming_with_chunk(
        setup: C41TypedSetupVerifierState,
        public_seed: [u8; 32],
        first_global_bit: usize,
        cells: usize,
        proof: &C41ResponseProof,
        delta: Fp2,
        chunk_cells: usize,
    ) -> Result<Self, AccelError> {
        Self::new_seed_streaming_inner(
            setup,
            public_seed,
            first_global_bit,
            cells,
            proof,
            delta,
            chunk_cells,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_seed_streaming_inner(
        setup: C41TypedSetupVerifierState,
        public_seed: [u8; 32],
        first_global_bit: usize,
        cells: usize,
        proof: &C41ResponseProof,
        delta: Fp2,
        chunk_cells: usize,
        diagnostics_handle: Option<Arc<Mutex<C41VerifierDiagnostics>>>,
    ) -> Result<Self, AccelError> {
        Self::validate_proof_geometry(cells, proof)?;
        let required_bits = cells
            .checked_mul(C41_BITS_PER_PACKED_CELL)
            .and_then(|bits| first_global_bit.checked_add(bits))
            .ok_or(AccelError::InvalidInput("C4.1 seed-only verifier range overflows"))?;
        if public_seed == [0; 32]
            || delta == Fp2::ZERO
            || setup.rows == 0
            || setup.keys.len() != setup.rows.saturating_mul(C41_SEED_BITS)
            || required_bits > setup.rows.saturating_mul(C41_PRG_USABLE_BITS)
            || chunk_cells == 0
        {
            return Err(AccelError::InvalidInput("invalid C4.1 seed-only verifier state"));
        }
        Ok(Self {
            key_source: C41VerifierKeySource::SeedOnly {
                public_seed,
                seed_keys: setup.keys.into_iter().map(VerifierKey::new).collect(),
                rows: setup.rows,
                first_global_bit,
                delta,
                chunk_cells,
            },
            d: proof.d.clone(),
            e: proof.e.clone(),
            segments: BTreeMap::new(),
            cursor: 0,
            bridge_corrections: proof.bridge_corrections.clone(),
            bridge_cursor: 0,
            bridges: Vec::new(),
            diagnostics_handle,
            diagnostics: C41VerifierDiagnostics { cells, ..Default::default() },
        })
    }

    pub fn is_seed_streaming(&self) -> bool {
        matches!(self.key_source, C41VerifierKeySource::SeedOnly { .. })
    }

    pub fn is_materialized(&self) -> bool {
        matches!(self.key_source, C41VerifierKeySource::Materialized { .. })
    }

    pub fn persistent_seed_bytes(&self) -> usize {
        match &self.key_source {
            C41VerifierKeySource::SeedOnly { seed_keys, .. } => {
                seed_keys.len() * std::mem::size_of::<VerifierKey>()
            }
            C41VerifierKeySource::Materialized { .. } => 0,
        }
    }

    pub fn has_domain(&self, domain: u64) -> bool {
        self.segments.contains_key(&domain)
    }

    pub fn register_matrix(
        &mut self,
        domain: u64,
        rows: usize,
        cols: usize,
        tx: &mut Transcript,
    ) -> Result<(), AccelError> {
        let started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let cells = rows
            .checked_mul(cols)
            .ok_or(AccelError::InvalidInput("C4.1 verifier segment overflows"))?;
        let end = self
            .cursor
            .checked_add(cells)
            .filter(|end| *end <= self.d.len())
            .ok_or(AccelError::InvalidInput("C4.1 verifier lot is exhausted"))?;
        if self.segments.contains_key(&domain) {
            return Err(AccelError::InvalidInput("duplicate C4.1 verifier segment"));
        }
        let mut d_bytes = Vec::with_capacity(2 * cells);
        for value in &self.d[self.cursor..end] {
            d_bytes.extend_from_slice(&value.to_le_bytes());
        }
        let e_values =
            (self.cursor..end).map(|cell| (self.e[cell / 8] >> (cell % 8)) & 1).collect::<Vec<_>>();
        tx.append_message(C41_PACKED_D_LABEL, &d_bytes);
        tx.append_message(C41_PACKED_E_LABEL, &packed_bits(&e_values));
        self.segments.insert(domain, C41ResponseSegment { offset: self.cursor, rows, cols });
        self.cursor = end;
        if let Some(started) = started {
            self.diagnostics.descriptor_build_s += started.elapsed().as_secs_f64();
            self.diagnostics.segments += 1;
        }
        Ok(())
    }

    fn bridge_query(
        &mut self,
        query: C41VerifierQuery,
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
    ) -> Result<VerifierKey, AccelError> {
        let started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let index = self.bridge_cursor;
        let correction = *self
            .bridge_corrections
            .get(index)
            .ok_or(AccelError::InvalidInput("truncated C4.1 bridge corrections"))?;
        self.bridge_cursor += 1;
        let domain = C41_BRIDGE_DOMAIN_BASE
            .checked_add(index as u64)
            .ok_or(AccelError::InvalidInput("C4.1 verifier bridge domain overflows"))?;
        tx.append_fp2s(C41_BRIDGE_LABEL, &[correction]);
        let ordinary = verifier.correct_full_verifier_key(domain, correction);
        self.bridges.push(C41VerifierBridge { query, ordinary });
        if let Some(started) = started {
            self.diagnostics.descriptor_build_s += started.elapsed().as_secs_f64();
            self.diagnostics.bridges += 1;
        }
        Ok(ordinary)
    }

    pub fn bridge_matrix(
        &mut self,
        domain: u64,
        rows: usize,
        cols: usize,
        point: &[Fp2],
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
    ) -> Result<VerifierKey, AccelError> {
        let segment = *self
            .segments
            .get(&domain)
            .ok_or(AccelError::InvalidInput("unknown C4.1 verifier matrix domain"))?;
        if segment.rows != rows || segment.cols != cols {
            return Err(AccelError::InvalidInput("C4.1 verifier matrix geometry differs"));
        }
        let col_bits = exact_bits(cols);
        if point.len() != col_bits + exact_bits(rows) {
            return Err(AccelError::InvalidInput("C4.1 matrix query point mismatch"));
        }
        let column_weights =
            crate::mle::eq_vec(&point[..col_bits]).into_iter().take(cols).collect::<Arc<[_]>>();
        let row_weights =
            crate::mle::eq_vec(&point[col_bits..]).into_iter().take(rows).collect::<Arc<[_]>>();
        self.bridge_query(
            C41VerifierQuery::Matrix { segment, row_weights, column_weights },
            verifier,
            tx,
        )
    }

    pub fn bridge_cache_columns(
        &mut self,
        segments: &[(u64, usize)],
        weights: &[Fp2],
        column_offset: usize,
        width: usize,
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
    ) -> Result<Vec<VerifierKey>, AccelError> {
        if weights.len() < width || width == 0 {
            return Err(AccelError::InvalidInput("C4.1 verifier cache-column weights differ"));
        }
        let weights = Arc::<[Fp2]>::from(weights[..width].to_vec());
        let mut output = Vec::with_capacity(segments.iter().map(|segment| segment.1).sum());
        for &(domain, rows) in segments {
            let segment = *self
                .segments
                .get(&domain)
                .ok_or(AccelError::InvalidInput("unknown C4.1 verifier cache segment"))?;
            if segment.rows != rows || column_offset + width > segment.cols {
                return Err(AccelError::InvalidInput(
                    "C4.1 verifier cache-column geometry differs",
                ));
            }
            for row in 0..rows {
                output.push(self.bridge_query(
                    C41VerifierQuery::CacheColumns {
                        segment,
                        row,
                        column_offset,
                        weights: weights.clone(),
                    },
                    verifier,
                    tx,
                )?);
            }
        }
        Ok(output)
    }

    pub fn bridge_cache_rows(
        &mut self,
        segments: &[(u64, usize)],
        weights: &[Fp2],
        column_offset: usize,
        width: usize,
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
    ) -> Result<Vec<VerifierKey>, AccelError> {
        let rows = segments.iter().map(|segment| segment.1).sum::<usize>();
        if weights.len() < rows {
            return Err(AccelError::InvalidInput("C4.1 verifier cache-row weights differ"));
        }
        if width == 0 {
            return Err(AccelError::InvalidInput("C4.1 verifier cache-row width is zero"));
        }
        let mut resolved = Vec::with_capacity(segments.len());
        for &(domain, segment_rows) in segments {
            let segment = *self
                .segments
                .get(&domain)
                .ok_or(AccelError::InvalidInput("unknown C4.1 verifier cache segment"))?;
            if segment.rows != segment_rows || column_offset + width > segment.cols {
                return Err(AccelError::InvalidInput("C4.1 verifier cache-row geometry differs"));
            }
            resolved.push(segment);
        }
        let segments = Arc::<[C41ResponseSegment]>::from(resolved);
        let weights = Arc::<[Fp2]>::from(weights[..rows].to_vec());
        let mut output = Vec::with_capacity(width);
        for column in 0..width {
            output.push(self.bridge_query(
                C41VerifierQuery::CacheRows {
                    segments: segments.clone(),
                    weights: weights.clone(),
                    column_offset,
                    column,
                },
                verifier,
                tx,
            )?);
        }
        Ok(output)
    }

    pub fn bridge_cache_matrix(
        &mut self,
        segments: &[(u64, usize)],
        row_weights: &[Fp2],
        column_weights: &[Fp2],
        column_offset: usize,
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
    ) -> Result<VerifierKey, AccelError> {
        let rows = segments.iter().map(|segment| segment.1).sum::<usize>();
        if row_weights.len() < rows || column_weights.is_empty() {
            return Err(AccelError::InvalidInput("C4.1 verifier cache matrix weights differ"));
        }
        let mut resolved = Vec::with_capacity(segments.len());
        for &(domain, segment_rows) in segments {
            let segment = *self
                .segments
                .get(&domain)
                .ok_or(AccelError::InvalidInput("unknown C4.1 verifier cache matrix segment"))?;
            if segment.rows != segment_rows || column_offset + column_weights.len() > segment.cols {
                return Err(AccelError::InvalidInput(
                    "C4.1 verifier cache matrix geometry differs",
                ));
            }
            resolved.push(segment);
        }
        self.bridge_query(
            C41VerifierQuery::CacheMatrix {
                segments: Arc::from(resolved),
                row_weights: Arc::from(row_weights[..rows].to_vec()),
                column_weights: Arc::from(column_weights.to_vec()),
                column_offset,
            },
            verifier,
            tx,
        )
    }

    pub fn finish(
        mut self,
        proof: &C41DegreeCloseProof,
        verifier: &mut VerifierCtx,
        tx: &mut Transcript,
        mut backend: Option<&mut Backend>,
    ) -> Result<bool, AccelError> {
        if self.cursor != self.d.len() || self.bridge_cursor != self.bridge_corrections.len() {
            return Err(AccelError::InvalidInput("incomplete C4.1 verifier consumption"));
        }
        let bridge_challenge = tx.challenge_c41_bridge_fp2();
        let mut bridge_power = Fp2::ONE;
        let mut bridge_powers = Vec::with_capacity(self.bridges.len());
        let mut ordinary = C41HdVerifier::public(verifier.delta, Fp2::ZERO);
        for bridge in &self.bridges {
            bridge_power = bridge_power * bridge_challenge;
            bridge_powers.push(bridge_power);
            ordinary = ordinary
                .add(C41HdVerifier::ordinary(bridge.ordinary).scale(bridge_power), verifier.delta);
        }
        let delta = verifier.delta;
        let chunk_cells = match &self.key_source {
            C41VerifierKeySource::Materialized { a_keys, b_keys, .. } => {
                if a_keys.len() != self.d.len() || b_keys.len() != self.d.len() {
                    return Err(AccelError::InvalidInput("C4.1 materialized verifier keys differ"));
                }
                C41_VERIFIER_STREAM_CHUNK_CELLS
            }
            C41VerifierKeySource::SeedOnly {
                seed_keys,
                rows,
                first_global_bit,
                delta: setup_delta,
                chunk_cells,
                ..
            } => {
                let required = self
                    .d
                    .len()
                    .checked_mul(C41_BITS_PER_PACKED_CELL)
                    .and_then(|bits| first_global_bit.checked_add(bits))
                    .ok_or(AccelError::InvalidInput("C4.1 seed-only verifier range overflows"))?;
                if *setup_delta != delta
                    || seed_keys.len() != rows.saturating_mul(C41_SEED_BITS)
                    || required > rows.saturating_mul(C41_PRG_USABLE_BITS)
                {
                    return Err(AccelError::InvalidInput(
                        "C4.1 seed-only verifier binding differs",
                    ));
                }
                *chunk_cells
            }
        };
        let mut a_key = Fp2::ZERO;
        let mut b_key = Fp2::ZERO;
        let mut public = Fp2::ZERO;
        for chunk_start in (0..self.d.len()).step_by(chunk_cells) {
            let chunk_end = (chunk_start + chunk_cells).min(self.d.len());
            let query_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
            let mut query = vec![Fp2::ZERO; chunk_end - chunk_start];
            for (bridge, power) in self.bridges.iter().zip(&bridge_powers) {
                bridge.query.add_to_chunk(chunk_start, &mut query, *power);
            }
            if let Some(started) = query_started {
                self.diagnostics.query_chunk_build_s += started.elapsed().as_secs_f64();
                self.diagnostics.chunks += 1;
                self.diagnostics.query_chunk_peak_bytes = self
                    .diagnostics
                    .query_chunk_peak_bytes
                    .max((query.len() * std::mem::size_of::<Fp2>()) as u64);
            }
            let fold_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
            let (chunk_a, chunk_b, chunk_public) = query
                .par_iter()
                .copied()
                .enumerate()
                .map(|(local, weight)| -> Result<(Fp2, Fp2, Fp2), AccelError> {
                    if weight == Fp2::ZERO {
                        return Ok((Fp2::ZERO, Fp2::ZERO, Fp2::ZERO));
                    }
                    let cell = chunk_start + local;
                    let (a, b) = match &self.key_source {
                        C41VerifierKeySource::Materialized { a_keys, b_keys, .. } => {
                            (a_keys[cell], b_keys[cell])
                        }
                        C41VerifierKeySource::SeedOnly {
                            public_seed,
                            seed_keys,
                            rows,
                            first_global_bit,
                            ..
                        } => c41_expand_packed_key_at(
                            *public_seed,
                            delta,
                            seed_keys,
                            *rows,
                            first_global_bit + cell * C41_BITS_PER_PACKED_CELL,
                        )
                        .map_err(AccelError::InvalidInput)?,
                    };
                    let e = (self.e[cell / 8] >> (cell % 8)) & 1;
                    let signed = if e == 0 { weight } else { Fp2::ZERO - weight };
                    let correction = i64::from(self.d[cell]) - (1 << 15) - (i64::from(e) << 16);
                    Ok((weight * a, signed * b, weight.mul_base(Fp::from_i64(correction))))
                })
                .try_reduce(
                    || (Fp2::ZERO, Fp2::ZERO, Fp2::ZERO),
                    |left, right| Ok((left.0 + right.0, left.1 + right.1, left.2 + right.2)),
                )?;
            if let Some(started) = fold_started {
                self.diagnostics.seed_expand_and_stream_fold_s += started.elapsed().as_secs_f64();
            }
            a_key += chunk_a;
            b_key += chunk_b;
            public += chunk_public;
        }
        let typed = C41HdVerifier {
            key: a_key - Fp2::from_base(Fp::new(1 << 16)) * b_key + fp2_pow(delta, 12) * public,
            degree: 12,
        };
        let relation = typed.sub(ordinary, delta);
        let mask_keys = verifier.expand_full_verifier_keys(C41_CLOSE_MASK_DOMAIN, 11);
        tx.append_message("c41_degree_close_frame", &[C41_CLOSE_MAGIC.as_slice(), &[12]].concat());
        let close_started = self.diagnostics_handle.as_ref().map(|_| Instant::now());
        let accepted = c41_degree_close_verify(relation, &mask_keys, delta, proof, tx);
        if let Some(started) = close_started {
            self.diagnostics.degree12_close_s = started.elapsed().as_secs_f64();
        }
        if let C41VerifierKeySource::Materialized { lot, .. } = &mut self.key_source {
            if let Some(lot) = lot.take() {
                let backend = backend.as_deref_mut().ok_or(AccelError::InvalidInput(
                    "C4.1 device-materialized verifier requires backend",
                ))?;
                backend.free_device(lot.a_keys)?;
                backend.free_device(lot.b_keys)?;
            }
        }
        if let Some(handle) = &self.diagnostics_handle {
            *handle.lock().expect("C4.1 verifier diagnostics mutex poisoned") =
                self.diagnostics.clone();
        }
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;
    use volta_mac::{
        auth_prover, auth_verifier, C41SecretChallengeChannel, C41SecretChallengeFrontier,
        CorrelationStream, VerifierCtx, RESERVED_DOMAIN_BITS,
    };

    struct FixedC41SecretChallenge(Fp2);

    impl C41SecretChallengeChannel for FixedC41SecretChallenge {
        fn challenge(&mut self, _frontier: C41SecretChallengeFrontier) -> Result<Fp2, String> {
            Ok(self.0)
        }
    }

    #[test]
    fn c41_domains_leave_mac_allocator_bits_clear() {
        assert_eq!(C41_BRIDGE_DOMAIN_BASE & RESERVED_DOMAIN_BITS, 0);
        assert_eq!(C41_CLOSE_MASK_DOMAIN & RESERVED_DOMAIN_BITS, 0);
    }

    #[test]
    fn folded_queries_match_direct_signed_sums_and_reject_non_bits() {
        let f = |x| Fp2::from_base(Fp::new(x));
        let query = [f(2), f(3), f(5)];
        let bitmap = [0b010];
        let mut a = Vec::new();
        let mut b = Vec::new();
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES as u64 {
            a.extend([f(lane + 1), f(lane + 2), f(lane + 3)]);
            b.extend([f(2 * lane + 1), f(2 * lane + 2), f(2 * lane + 3)]);
        }
        let folded = c41_fold_typed_queries_reference(&a, &b, &query, &bitmap).unwrap();
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
            assert_eq!(
                folded.a[lane],
                query[0] * a[3 * lane] + query[1] * a[3 * lane + 1] + query[2] * a[3 * lane + 2]
            );
            assert_eq!(
                folded.b[lane],
                query[0] * b[3 * lane] - query[1] * b[3 * lane + 1] + query[2] * b[3 * lane + 2]
            );
        }
        assert!(c41_fold_typed_queries_reference(&a, &b, &query, &[0b1000]).is_err());
    }

    #[test]
    fn xor4_maj7_polynomial_matches_bits_and_verifier_evaluation() {
        let delta = Fp2::new(Fp::new(17), Fp::new(19));
        for pattern in 0u16..(1 << 11) {
            let mut seed = vec![ProverSubAuthed::new(Fp::ZERO, Fp2::ZERO); C41_SEED_BITS];
            let mut keys = vec![VerifierKey::ZERO; C41_SEED_BITS];
            for index in 0..11 {
                let bit = Fp::new(u64::from((pattern >> index) & 1));
                let tag = Fp2::new(Fp::new(index as u64 + 3), Fp::new(index as u64 + 29));
                seed[index] = ProverSubAuthed::new(bit, tag);
                keys[index] = VerifierKey::new(tag + delta.mul_base(bit));
            }
            let sigma = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let prover = c41_xor4_maj7_prover(&seed, sigma).unwrap();
            let verifier = c41_xor4_maj7_verifier(delta, &keys, sigma).unwrap();
            let xor = ((pattern & 0b1111).count_ones() & 1) as u64;
            let majority = (((pattern >> 4) & 0b111_1111).count_ones() >= 4) as u64;
            assert_eq!(prover.degree, 12);
            assert_eq!(prover.value(), Fp2::from_base(Fp::new(xor ^ majority)));
            assert_eq!(prover.eval(delta), verifier.key);
        }
    }

    #[test]
    fn masked_degree_closes_are_complete_canonical_and_reject_tampering() {
        let delta = Fp2::new(Fp::new(101), Fp::new(103));
        let mut prover_stream = CorrelationStream::new([41; 32]);
        let mut verifier = VerifierCtx::new([41; 32], delta);
        let mut prover_tx = Transcript::new([42; 32]);
        let mut verifier_tx = Transcript::new([42; 32]);
        let bits = (0..C41_SEED_BITS).map(|index| (index & 1) as i16).collect::<Vec<_>>();
        let (corrections, authed) = auth_prover(&mut prover_stream, 0x4100, &bits, &mut prover_tx);
        let keys = auth_verifier(&mut verifier, 0x4100, &corrections);

        let challenge = Fp2::new(Fp::new(107), Fp::new(109));
        let prover_relation = c41_batch_relation_prover(
            authed.iter().copied().map(c41_bit_relation_prover),
            challenge,
        )
        .unwrap();
        let verifier_relation = c41_batch_relation_verifier(
            delta,
            keys.iter().copied().map(|key| c41_bit_relation_verifier(delta, key)),
            challenge,
        )
        .unwrap();
        let masks = prover_stream.draw_fulls(0x4101, 1);
        let mask_keys = verifier.expand_full_verifier_keys(0x4101, 1);
        let proof = c41_degree_close_prover(prover_relation, &masks, &mut prover_tx).unwrap();
        assert!(c41_degree_close_verify(
            verifier_relation,
            &mask_keys,
            delta,
            &proof,
            &mut verifier_tx,
        ));

        let sigma = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let output = c41_xor4_maj7_prover(&authed, sigma).unwrap();
        let output_key = c41_xor4_maj7_verifier(delta, &keys, sigma).unwrap();
        let relation = output.sub(C41HdProver::public(output.value()));
        let relation_key = output_key.sub(C41HdVerifier::public(delta, output.value()), delta);
        let masks = prover_stream.draw_fulls(0x4102, 11);
        let mask_keys = verifier.expand_full_verifier_keys(0x4102, 11);
        let proof = c41_degree_close_prover(relation, &masks, &mut prover_tx).unwrap();
        let encoded = proof.encode_degree12().unwrap();
        assert_eq!(encoded.len(), C41_DEGREE12_CLOSE_BYTES);
        let decoded = C41DegreeCloseProof::decode_degree12(&encoded).unwrap();
        assert!(c41_degree_close_verify(
            relation_key,
            &mask_keys,
            delta,
            &decoded,
            &mut verifier_tx,
        ));
        let mut changed = decoded;
        changed.coefficients[0] += Fp2::ONE;
        assert!(!c41_degree_close_verify(
            relation_key,
            &mask_keys,
            delta,
            &changed,
            &mut Transcript::new([42; 32]),
        ));
    }

    #[test]
    fn packed_setup_crosses_expansions_and_roundtrips_signed_i16() {
        let public_seed = [0xC4; 32];
        let delta = Fp2::new(Fp::new(211), Fp::new(223));
        let mut prover_rows = Vec::new();
        let mut verifier_rows = Vec::new();
        for row in 0..2 {
            let mut prover = Vec::with_capacity(C41_SEED_BITS);
            let mut verifier = Vec::with_capacity(C41_SEED_BITS);
            for index in 0..C41_SEED_BITS {
                let bit = Fp::new(((row * C41_SEED_BITS + index) % 3 == 0) as u64);
                let tag = Fp2::new(
                    Fp::new((row * C41_SEED_BITS + index + 1) as u64),
                    Fp::new((row * C41_SEED_BITS + index + 7) as u64),
                );
                prover.push(ProverSubAuthed::new(bit, tag));
                verifier.push(VerifierKey::new(tag + delta.mul_base(bit)));
            }
            prover_rows.push(prover);
            verifier_rows.push(verifier);
        }
        let first = C41_PRG_USABLE_BITS - 9;
        let prover =
            c41_expand_packed_cells_reference(public_seed, &prover_rows, first, 2).unwrap();
        let verifier =
            c41_expand_packed_keys_reference(public_seed, delta, &verifier_rows, first, 2).unwrap();
        let flat_keys = verifier_rows.iter().flatten().copied().collect::<Vec<_>>();
        let materialized = c41_materialize_packed_keys(
            public_seed,
            delta,
            &C41TypedSetupVerifierState {
                keys: flat_keys.iter().map(|key| key.k).collect(),
                rows: verifier_rows.len(),
            },
            first,
            2,
        )
        .unwrap();
        assert_eq!(materialized, verifier);
        let checksum = c41_seed_streaming_checksum(
            &C41TypedSetupVerifierState {
                keys: flat_keys.iter().map(|key| key.k).collect(),
                rows: verifier_rows.len(),
            },
            public_seed,
            first,
            2,
            delta,
            1,
        )
        .unwrap();
        assert_eq!(checksum.0, verifier.a_keys.iter().copied().fold(Fp2::ZERO, |a, b| a + b));
        assert_eq!(checksum.1, verifier.b_keys.iter().copied().fold(Fp2::ZERO, |a, b| a + b));
        for cell in 0..2 {
            assert_eq!(
                c41_expand_packed_key_at(
                    public_seed,
                    delta,
                    &flat_keys,
                    verifier_rows.len(),
                    first + cell * C41_BITS_PER_PACKED_CELL,
                )
                .unwrap(),
                (verifier.a_keys[cell], verifier.b_keys[cell]),
            );
            let mut a = [Fp2::ZERO; C41_MAX_DEGREE + 1];
            let mut b = [Fp2::ZERO; C41_MAX_DEGREE + 1];
            for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
                a[lane] = prover.a[lane * 2 + cell];
                b[lane] = prover.b[lane * 2 + cell];
            }
            a[12] = Fp2::from_base(Fp::new(u64::from(prover.a_values[cell])));
            b[12] =
                Fp2::from_base(Fp::new(u64::from((prover.b_bitmap[cell / 8] >> (cell % 8)) & 1)));
            assert_eq!(
                C41HdProver { coefficients: a, degree: 12 }.eval(delta),
                verifier.a_keys[cell]
            );
            assert_eq!(
                C41HdProver { coefficients: b, degree: 12 }.eval(delta),
                verifier.b_keys[cell]
            );
        }

        let values = [i16::MIN, i16::MAX];
        let corrections =
            c41_pack_corrections(&values, &prover.a_values, &prover.b_bitmap).unwrap();
        assert_eq!(c41_unpack_corrections(&prover, &corrections).unwrap(), values);
    }

    #[test]
    fn compact_verifier_queries_match_dense_entries_across_chunks() {
        let f = |value| Fp2::from_base(Fp::new(value));
        let first = C41ResponseSegment { offset: 2, rows: 2, cols: 3 };
        let second = C41ResponseSegment { offset: 10, rows: 1, cols: 3 };
        let queries = [
            C41VerifierQuery::Matrix {
                segment: first,
                row_weights: Arc::from(vec![f(2), f(3)]),
                column_weights: Arc::from(vec![f(5), f(7), f(11)]),
            },
            C41VerifierQuery::CacheColumns {
                segment: first,
                row: 1,
                column_offset: 1,
                weights: Arc::from(vec![f(13), f(17)]),
            },
            C41VerifierQuery::CacheRows {
                segments: Arc::from(vec![first, second]),
                weights: Arc::from(vec![f(19), f(23), f(29)]),
                column_offset: 0,
                column: 2,
            },
            C41VerifierQuery::CacheMatrix {
                segments: Arc::from(vec![first, second]),
                row_weights: Arc::from(vec![f(31), f(37), f(41)]),
                column_weights: Arc::from(vec![f(43), f(47)]),
                column_offset: 1,
            },
        ];
        let powers = [f(53), f(59), f(61), f(67)];
        let mut chunked = vec![Fp2::ZERO; 13];
        for start in (0..chunked.len()).step_by(4) {
            let end = (start + 4).min(chunked.len());
            for (query, power) in queries.iter().zip(powers) {
                query.add_to_chunk(start, &mut chunked[start..end], power);
            }
        }

        let mut dense = vec![Fp2::ZERO; 13];
        for row in 0..first.rows {
            for column in 0..first.cols {
                dense[first.offset + row * first.cols + column] +=
                    powers[0] * [f(2), f(3)][row] * [f(5), f(7), f(11)][column];
            }
        }
        dense[first.offset + first.cols + 1] += powers[1] * f(13);
        dense[first.offset + first.cols + 2] += powers[1] * f(17);
        for (segment, offset) in [(first, 0), (second, 2)] {
            for row in 0..segment.rows {
                dense[segment.offset + row * segment.cols + 2] +=
                    powers[2] * [f(19), f(23), f(29)][offset + row];
                for column in 0..2 {
                    dense[segment.offset + row * segment.cols + 1 + column] +=
                        powers[3] * [f(31), f(37), f(41)][offset + row] * [f(43), f(47)][column];
                }
            }
        }
        assert_eq!(chunked, dense);
    }

    #[test]
    fn seed_streaming_finish_accepts_honest_reduced_geometry() {
        let delta = Fp2::new(Fp::new(71), Fp::new(73));
        let public_seed = [0xC4; 32];
        let pcg_seed = [0x45; 32];
        let cells = 8;
        let segment = C41ResponseSegment { offset: 0, rows: 2, cols: 4 };
        let point = vec![Fp2::new(Fp::new(5), Fp::new(7)); 3];
        let query = matrix_query(segment.rows, segment.cols, &point).unwrap();

        let mut prover = CorrelationStream::new(pcg_seed);
        let bits = (0..C41_SEED_BITS).map(|index| (index % 5 == 0) as i16).collect::<Vec<_>>();
        let (seed_corrections, seed_values) =
            auth_prover(&mut prover, 0x4110, &bits, &mut Transcript::new([1; 32]));
        let lot = c41_expand_packed_cells_reference(
            public_seed,
            std::slice::from_ref(&seed_values),
            0,
            cells,
        )
        .unwrap();
        let plaintexts = [i16::MIN, -1234, -1, 0, 1, 2345, 30_000, i16::MAX];
        let corrections = c41_pack_corrections(&plaintexts, &lot.a_values, &lot.b_bitmap).unwrap();
        let bridge_value = query.iter().zip(plaintexts).fold(Fp2::ZERO, |sum, (weight, value)| {
            sum + *weight * Fp2::from_base(Fp::from_i64(i64::from(value)))
        });

        let bridge_corr = prover.draw_fulls(C41_BRIDGE_DOMAIN_BASE, 1)[0];
        let bridge_correction = bridge_value - bridge_corr.x;
        let ordinary = bridge_corr.authenticate(bridge_value);
        let secret_challenge = Fp2::new(Fp::new(101), Fp::new(103));
        let mut prover_tx = Transcript::new_c41_secret_challenge(
            [0x46; 32],
            Box::new(FixedC41SecretChallenge(secret_challenge)),
        )
        .unwrap();
        prover_tx.append_fp2s(C41_BRIDGE_LABEL, &[bridge_correction]);
        let challenge = prover_tx.challenge_c41_bridge_fp2();
        let scaled_query = query.iter().map(|weight| challenge * *weight).collect::<Vec<_>>();
        let ordinary = ordinary.scale(challenge);
        let radix = Fp2::from_base(Fp::new(1 << 16));
        let mut coefficients = [Fp2::ZERO; C41_MAX_DEGREE + 1];
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
            for (cell, weight) in scaled_query.iter().copied().enumerate() {
                coefficients[lane] += weight * lot.a[lane * cells + cell];
                let e = (corrections.e[cell / 8] >> (cell % 8)) & 1;
                let signed = if e == 0 { weight } else { Fp2::ZERO - weight };
                coefficients[lane] =
                    coefficients[lane] - radix * signed * lot.b[lane * cells + cell];
            }
        }
        coefficients[12] = ordinary.x;
        let relation =
            C41HdProver { coefficients, degree: 12 }.sub(C41HdProver::ordinary(ordinary));
        assert_eq!(relation.value(), Fp2::ZERO);
        let masks = prover.draw_fulls(C41_CLOSE_MASK_DOMAIN, 11);
        prover_tx.append_message(
            "c41_degree_close_frame",
            &[C41_CLOSE_MAGIC.as_slice(), &[12]].concat(),
        );
        let close = c41_degree_close_prover(relation, &masks, &mut prover_tx).unwrap();

        let run_verifier = |threads, materialized| {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            pool.install(|| {
                let diagnostics = Arc::new(Mutex::new(C41VerifierDiagnostics::default()));
                let mut verifier = VerifierCtx::new(pcg_seed, delta);
                let seed_keys = auth_verifier(&mut verifier, 0x4110, &seed_corrections);
                let bridge_key =
                    verifier.correct_full_verifier_key(C41_BRIDGE_DOMAIN_BASE, bridge_correction);
                let key_source = if materialized {
                    let lot = c41_expand_packed_keys_reference(
                        public_seed,
                        delta,
                        std::slice::from_ref(&seed_keys),
                        0,
                        cells,
                    )
                    .unwrap();
                    C41VerifierKeySource::Materialized {
                        lot: None,
                        a_keys: lot.a_keys,
                        b_keys: lot.b_keys,
                    }
                } else {
                    C41VerifierKeySource::SeedOnly {
                        public_seed,
                        seed_keys,
                        rows: 1,
                        first_global_bit: 0,
                        delta,
                        chunk_cells: 3,
                    }
                };
                let state = C41VerifierResponseState {
                    key_source,
                    d: corrections.d.clone(),
                    e: corrections.e.clone(),
                    segments: BTreeMap::from([(0x4120, segment)]),
                    cursor: cells,
                    bridge_corrections: vec![bridge_correction],
                    bridge_cursor: 1,
                    bridges: vec![C41VerifierBridge {
                        query: C41VerifierQuery::Matrix {
                            segment,
                            row_weights: Arc::from(crate::mle::eq_vec(&point[2..])),
                            column_weights: Arc::from(crate::mle::eq_vec(&point[..2])),
                        },
                        ordinary: bridge_key,
                    }],
                    diagnostics_handle: Some(diagnostics.clone()),
                    diagnostics: C41VerifierDiagnostics { cells, ..Default::default() },
                };
                let mut transcript = Transcript::new_c41_secret_challenge(
                    [0x46; 32],
                    Box::new(FixedC41SecretChallenge(secret_challenge)),
                )
                .unwrap();
                transcript.append_fp2s(C41_BRIDGE_LABEL, &[bridge_correction]);
                assert!(state.finish(&close, &mut verifier, &mut transcript, None).unwrap());
                let measured = diagnostics.lock().unwrap().clone();
                assert_eq!(measured.cells, cells);
                assert_eq!(measured.chunks, if materialized { 1 } else { 3 });
                assert_eq!(
                    measured.query_chunk_peak_bytes,
                    if materialized { cells * 16 } else { 3 * 16 } as u64
                );
                transcript.canonical_binding_digest().unwrap()
            })
        };
        let expected = prover_tx.canonical_binding_digest().unwrap();
        assert_eq!(run_verifier(1, false), expected);
        assert_eq!(run_verifier(4, false), expected);
        assert_eq!(run_verifier(4, true), expected);
    }

    #[test]
    fn typed_setup_is_party_separated_exactly_counted_and_rejects_bad_codec() {
        let delta = Fp2::new(Fp::new(307), Fp::new(311));
        let mut prover_stream = CorrelationStream::new([0x51; 32]);
        let mut verifier = VerifierCtx::new([0x51; 32], delta);
        let mut prover_tx = Transcript::new([0x52; 32]);
        let mut verifier_tx = Transcript::new([0x52; 32]);
        let exchange = c41_typed_setup_exchange(
            [0x53; 32],
            [0x54; 32],
            2,
            0x4200,
            0x4300,
            &mut prover_stream,
            &mut verifier,
            &mut prover_tx,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(exchange.prover.bits.len(), 2 * C41_SEED_BITS);
        assert_eq!(exchange.prover.tags.len(), exchange.prover.bits.len());
        assert_eq!(exchange.verifier.keys.len(), exchange.prover.bits.len());
        for index in 0..exchange.prover.bits.len() {
            assert_eq!(
                exchange.verifier.keys[index],
                exchange.prover.tags[index]
                    + delta.mul_base(Fp::new(u64::from(exchange.prover.bits[index])))
            );
        }
        let encoded = exchange.proof.encode().unwrap();
        assert_eq!(encoded.len(), 12 + 2 * (9 + 8 * C41_SEED_BITS) + 41);
        assert_eq!(exchange.metrics.prover_to_verifier_bytes, encoded.len() as u64);
        assert_eq!(exchange.metrics.verifier_to_prover_bytes, 48);
        assert!(exchange.metrics.conditional_soundness_bits > 78.0);
        assert!(exchange.metrics.conditional_weight_zk_bits > 78.0);
        assert_eq!(C41TypedSetupProof::decode(&encoded).unwrap(), exchange.proof);
        assert!(C41TypedSetupProof::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut changed = encoded;
        changed[12] ^= 1;
        assert!(C41TypedSetupProof::decode(&changed).is_err());
    }

    #[test]
    fn typed_seed_bitness_close_refuses_non_bits() {
        let invalid = ProverSubAuthed::new(Fp::new(2), Fp2::new(Fp::new(7), Fp::new(11)));
        let relation = c41_bit_relation_prover(invalid);
        assert_ne!(relation.value(), Fp2::ZERO);
        let mut stream = CorrelationStream::new([0x61; 32]);
        let masks = stream.draw_fulls(0x4400, 1);
        assert!(
            c41_degree_close_prover(relation, &masks, &mut Transcript::new([0x62; 32]),).is_err()
        );
    }
}

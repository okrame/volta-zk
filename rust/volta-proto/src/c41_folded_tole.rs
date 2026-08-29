//! C4.1 folded-query high-degree typed OLE primitives.
//!
//! A degree-`d` authenticated value is represented by a polynomial whose
//! coefficient at `X^d` is the plaintext and whose evaluation at the
//! verifier-only `Delta` is the verifier key.  The prover stores only the
//! lower coefficients in response slabs; the semantic top coefficient is
//! reconstructed from the Packed16 correction.

use volta_accel::{AccelError, Backend, DeviceBuffer, Fp2Repr};
use volta_field::{Fp, Fp2, FpStream, P};
use volta_mac::{
    auth_prover, auth_verifier, CorrelationStream, FullCorr, ProverSubAuthed, Transcript,
    VerifierCtx, VerifierKey,
};

pub const C41_TYPED_POLYNOMIAL_LANES: usize = 12;
pub const C41_MAX_DEGREE: usize = 12;
pub const C41_SEED_BITS: usize = 1024;
pub const C41_PRG_OUTPUT_BITS: usize = 1 << 20;
pub const C41_PRG_USABLE_BITS: usize = C41_PRG_OUTPUT_BITS - C41_SEED_BITS;
pub const C41_BITS_PER_PACKED_CELL: usize = 17;
pub const C41_DEGREE12_CLOSE_BYTES: usize = 201;

const C41_CLOSE_MAGIC: &[u8; 8] = b"C41D12\0\0";
const C41_BITNESS_CLOSE_MAGIC: &[u8; 8] = b"C41D02\0\0";
const C41_SETUP_MAGIC: &[u8; 8] = b"C41TS1\0\0";
const C41_SETUP_VERSION: u16 = 1;
const C41_SETUP_ROW_HEADER_BYTES: usize = 9;
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

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;
    use volta_mac::{auth_prover, auth_verifier, CorrelationStream, VerifierCtx};

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
        for cell in 0..2 {
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

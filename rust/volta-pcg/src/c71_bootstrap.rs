//! C7.1 B9: isolated MR19 receiver-first / Wolverine base-sVOLE component.
//!
//! Source mapping and unresolved admission obligations: design §10, B9.
//! The opt-in B11 profile uses bounded AES-256 GGM expansion inside COPE.
//! Neither profile has production or PCS admission. The separate opt-in
//! `c71_lifetime` module wraps B11 with a durable finite-pool component.
//! Callers must supply an authenticated, dedicated channel.
//! OS randomness is mandatory in the public entry points. Errors consume the
//! channel and discard secret buffers; in-memory ownership is not a durable burn.

use p521::{
    elliptic_curve::{
        ff::PrimeField,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint as Point, Scalar,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{
    io::{self, Read, Write},
    time::Instant,
};
use volta_field::{Fp, Fp3, P};
use zeroize::{Zeroize, Zeroizing};

const OTS: usize = 576;
const POINT_BYTES: usize = 67;
const MAX_ROWS: usize = 27_511;
const MAGIC: &[u8; 8] = b"C71B9v01";
#[derive(Clone, Copy)]
pub(super) struct Mr19Profile {
    pub(super) ot_count: usize,
    pub(super) group_receiver_domain: &'static [u8],
    pub(super) seed_sender_domain: &'static [u8],
}
pub(super) const LEGACY_MR19: Mr19Profile = Mr19Profile {
    ot_count: OTS,
    group_receiver_domain: b"C71B9/group/receiver/",
    seed_sender_domain: b"C71B9/seed/sender/",
};
/// One initial B12 capacity. The nine check masks are never returned as data.
#[cfg(feature = "c71-b11")]
pub const MAX_FIXED_RUN_ROWS: usize = (1 << 24) - 9;
#[derive(Clone, Copy)]
enum Suite {
    B9,
    #[cfg(feature = "c71-b11")]
    B11,
    #[cfg(feature = "c71-b11")]
    B12FixedRun,
}
type Result<T> = io::Result<T>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Caller-provided public binding, taken by value. No persistent-state claim.
pub struct Context {
    pub session: [u8; 32],
    pub channel: [u8; 32],
    pub capacity: [u8; 32],
    pub rows: usize,
}
impl Context {
    #[cfg(test)]
    fn common(&self) -> Result<Vec<u8>> {
        self.common_for(Suite::B9)
    }
    fn common_for(&self, suite: Suite) -> Result<Vec<u8>> {
        let (magic, id, max_rows) = match suite {
            Suite::B9 => (MAGIC, 1u32, MAX_ROWS),
            #[cfg(feature = "c71-b11")]
            Suite::B11 => (b"C71B11v1", 2u32, 207),
            #[cfg(feature = "c71-b11")]
            Suite::B12FixedRun => (b"C71B12F1", 3u32, MAX_FIXED_RUN_ROWS),
        };
        if !(1..=max_rows).contains(&self.rows)
            || self.rows.checked_add(9).and_then(|n| n.checked_mul(OTS * 8)).is_none()
            || [&self.session, &self.channel, &self.capacity].iter().any(|v| **v == [0; 32])
        {
            return Err(invalid("invalid bootstrap context or row capacity"));
        }
        let mut out = Vec::with_capacity(120);
        out.extend(magic);
        out.extend(self.session);
        out.extend(self.channel);
        out.extend(self.capacity);
        out.extend((self.rows as u64).to_le_bytes());
        out.extend(id.to_le_bytes());
        out.extend(9u32.to_le_bytes());
        Ok(out)
    }
}

/// Native calls, not an inclusive CPU-instruction or base-field census.
#[derive(Default, Debug, Serialize)]
pub struct Work {
    pub fixed_scalar_mul: u64,
    pub variable_scalar_mul: u64,
    pub point_add: u64,
    pub group_hash: u64,
    pub group_candidates: u64,
    pub kdf: u64,
    pub scalar_candidates: u64,
    pub field_candidates: u64,
    pub prf_field_outputs: u64,
    pub aes_key_schedules: u64,
    pub aes_block_encryptions: u64,
    pub cope_gadget_products: u64,
    pub check_base_products: u64,
    pub check_fp9_products: u64,
    pub compression_fp3_products: u64,
}
#[derive(Default, Debug, Serialize)]
pub struct Audit {
    pub work: Work,
    pub sent_frames: Vec<(u8, usize)>,
    pub received_frames: Vec<(u8, usize)>,
    pub phase_seconds: Vec<(&'static str, f64)>,
}
impl Audit {
    fn phase(&mut self, name: &'static str, start: Instant) {
        self.phase_seconds.push((name, start.elapsed().as_secs_f64()));
    }
}

/// Quarantined component output, deliberately not a PCG pool.
pub struct ProverOutput {
    pub values: Zeroizing<Vec<u64>>,
    pub tags: Zeroizing<Vec<[u64; 3]>>,
    pub audit: Audit,
}
pub struct VerifierOutput {
    pub delta: Zeroizing<[u64; 3]>,
    pub keys: Zeroizing<Vec<[u64; 3]>>,
    pub audit: Audit,
}

// Canonical limbs allow volatile erasure without changing the shared field type.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct F9([u64; 9]);
impl Zeroize for F9 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl F9 {
    fn basis(h: usize) -> Self {
        let mut v = Self::default();
        v.0[h] = 1;
        v
    }
    fn add(self, rhs: Self) -> Self {
        Self(std::array::from_fn(|i| (Fp::new(self.0[i]) + Fp::new(rhs.0[i])).value()))
    }
    fn scale(self, rhs: u64) -> Self {
        Self(self.0.map(|v| (Fp::new(v) * Fp::new(rhs)).value()))
    }
    fn mul(self, rhs: Self, work: &mut Work) -> Self {
        work.check_fp9_products += 1;
        let mut out = [Fp::ZERO; 9];
        for i in 0..9 {
            for j in 0..9 {
                let product = Fp::new(self.0[i]) * Fp::new(rhs.0[j]);
                // w^9=2. The wrap factor uses addition, not another product.
                out[(i + j) % 9] += if i + j >= 9 { product + product } else { product };
            }
        }
        Self(out.map(Fp::value))
    }
    fn compress(self, alpha: &[F9], work: &mut Work) -> [u64; 3] {
        let mut out = Fp3::ZERO;
        for t in 0..3 {
            work.compression_fp3_products += 1;
            out += fp3([alpha[0].0[3 * t], alpha[0].0[3 * t + 1], alpha[0].0[3 * t + 2]])
                * fp3([self.0[t], self.0[t + 3], self.0[t + 6]]);
        }
        [out.c0.value(), out.c1.value(), out.c2.value()]
    }
}
fn fp3(a: [u64; 3]) -> Fp3 {
    Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]))
}

fn random_bytes(rng: &mut (impl RngCore + CryptoRng), out: &mut [u8]) -> Result<()> {
    rng.try_fill_bytes(out).map_err(|_| invalid("OS randomness unavailable"))
}
fn scalar(rng: &mut (impl RngCore + CryptoRng), work: &mut Work) -> Result<Zeroizing<Scalar>> {
    let mut raw = Zeroizing::new([0u8; 66]);
    let mut result = Zeroizing::new(Scalar::ZERO);
    let mut found = Choice::from(0);
    for _ in 0..8 {
        work.scalar_candidates += 1;
        random_bytes(rng, &mut raw[..])?;
        raw[0] &= 1;
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(&raw[..]);
        let candidate = Scalar::from_repr(repr);
        let valid = candidate.is_some();
        *result =
            Scalar::conditional_select(&result, &candidate.unwrap_or(Scalar::ZERO), valid & !found);
        found |= valid;
    }
    if bool::from(found) {
        Ok(result)
    } else {
        Err(invalid("scalar sampling exhausted"))
    }
}
fn sample_fp(mut draw: impl FnMut(&mut [u8]) -> Result<()>, work: &mut Work) -> Result<u64> {
    let mut raw = Zeroizing::new([0u8; 8]);
    let mut result = 0u64;
    let mut found = Choice::from(0);
    for _ in 0..8 {
        work.field_candidates += 1;
        draw(&mut raw[..])?;
        let x = u64::from_le_bytes(*raw);
        let valid = Choice::from((x < P) as u8);
        result = u64::conditional_select(&result, &x, valid & !found);
        found |= valid;
    }
    // A sender knows both PRF streams: early exit could reveal the OT choice.
    if bool::from(found) {
        Ok(result)
    } else {
        Err(invalid("Fp sampling exhausted"))
    }
}
fn random_f9(rng: &mut (impl RngCore + CryptoRng), work: &mut Work) -> Result<F9> {
    let mut out = F9::default();
    for limb in &mut out.0 {
        *limb = sample_fp(|v| random_bytes(rng, v), work)?;
    }
    Ok(out)
}
fn encode(point: &Point) -> [u8; POINT_BYTES] {
    let encoded = point.to_encoded_point(true);
    let mut out = [0u8; POINT_BYTES];
    // Public points, or both receiver DH results, are encoded in each OT.
    if encoded.as_bytes().len() == POINT_BYTES {
        out.copy_from_slice(encoded.as_bytes());
    }
    out
}
fn decode(raw: &[u8]) -> Result<Point> {
    if raw.len() != POINT_BYTES {
        return Err(invalid("point length"));
    }
    if raw == [0u8; POINT_BYTES] {
        return Ok(Point::IDENTITY);
    }
    if raw[0] != 2 && raw[0] != 3 {
        return Err(invalid("point prefix"));
    }
    let sec1 = EncodedPoint::from_bytes(raw).map_err(|_| invalid("point encoding"))?;
    let a = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&sec1))
        .ok_or_else(|| invalid("noncanonical or off-curve point"))?;
    let p = Point::from(a);
    if encode(&p) != raw {
        return Err(invalid("noncanonical point"));
    }
    Ok(p)
}
fn shake(domain: &[u8], context: &[u8], i: usize, j: u8, point: &Point) -> Shake256 {
    let mut h = Shake256::default();
    h.update(domain);
    h.update(context);
    h.update(&(i as u32).to_le_bytes());
    h.update(&[j]);
    h.update(&encode(point));
    h
}
fn group_hash_for(
    domain: &[u8],
    context: &[u8],
    i: usize,
    j: u8,
    p: &Point,
    work: &mut Work,
) -> Result<Point> {
    work.group_hash += 1;
    let base = shake(domain, context, i, j, p);
    for trial in 0u16..512 {
        work.group_candidates += 1;
        let mut h = base.clone();
        h.update(&trial.to_le_bytes());
        let mut candidate = [0u8; 66];
        XofReader::read(&mut h.finalize_xof(), &mut candidate);
        candidate[0] &= 3; // 522 low bits, x followed by its sign
        let sign = candidate[65] & 1;
        for k in (1..66).rev() {
            candidate[k] = (candidate[k] >> 1) | (candidate[k - 1] << 7);
        }
        candidate[0] >>= 1;
        if candidate[0] == 1 && candidate[1..].iter().all(|&x| x == 255) {
            if sign == 0 {
                return Ok(Point::IDENTITY);
            }
            continue;
        }
        let mut raw = [0u8; POINT_BYTES];
        raw[0] = 2 + sign;
        raw[1..].copy_from_slice(&candidate);
        if let Ok(p) = decode(&raw) {
            return Ok(p);
        }
    }
    Err(invalid("group sampling exhausted"))
}
#[cfg(test)]
fn group_hash(context: &[u8], i: usize, j: u8, p: &Point, work: &mut Work) -> Result<Point> {
    group_hash_for(LEGACY_MR19.group_receiver_domain, context, i, j, p, work)
}
fn kdf_for(
    domain: &[u8],
    context: &[u8],
    i: usize,
    j: u8,
    p: &Point,
    work: &mut Work,
) -> Zeroizing<[u8; 32]> {
    work.kdf += 1;
    let mut out = Zeroizing::new([0u8; 32]);
    XofReader::read(&mut shake(domain, context, i, j, p).finalize_xof(), &mut out[..]);
    out
}
#[cfg(test)]
fn kdf(context: &[u8], i: usize, j: u8, p: &Point, work: &mut Work) -> Zeroizing<[u8; 32]> {
    kdf_for(LEGACY_MR19.seed_sender_domain, context, i, j, p, work)
}
fn fixed(s: &Scalar, w: &mut Work) -> Point {
    w.fixed_scalar_mul += 1;
    Point::GENERATOR * s
}
fn variable(p: &Point, s: &Scalar, w: &mut Work) -> Zeroizing<Point> {
    w.variable_scalar_mul += 1;
    Zeroizing::new(p * s)
}

fn send_header(channel: &mut impl Write, tag: u8, size: usize) -> Result<()> {
    channel.write_all(&[tag])?;
    channel.write_all(&(size as u64).to_le_bytes())
}
fn send(channel: &mut impl Write, tag: u8, data: &[u8], audit: &mut Audit) -> Result<()> {
    send_header(channel, tag, data.len())?;
    channel.write_all(data)?;
    channel.flush()?;
    audit.sent_frames.push((tag, data.len() + 9));
    Ok(())
}
fn recv(
    channel: &mut impl Read,
    tag: u8,
    size: usize,
    audit: &mut Audit,
) -> Result<Zeroizing<Vec<u8>>> {
    recv_header(channel, tag, size)?;
    // Check the length before allocation; no attacker-controlled capacity.
    let mut data = Zeroizing::new(vec![0u8; size]);
    channel.read_exact(&mut data)?;
    audit.received_frames.push((tag, size + 9));
    Ok(data)
}
fn recv_header(channel: &mut impl Read, tag: u8, size: usize) -> Result<()> {
    let mut header = [0u8; 9];
    channel.read_exact(&mut header)?;
    if header[0] != tag || u64::from_le_bytes(header[1..].try_into().unwrap()) != size as u64 {
        return Err(invalid("frame order or exact length"));
    }
    Ok(())
}
fn handshake(
    channel: &mut (impl Read + Write),
    context: &Context,
    prover: bool,
    rng: &mut (impl RngCore + CryptoRng),
    audit: &mut Audit,
    suite: Suite,
) -> Result<Vec<u8>> {
    let common = context.common_for(suite)?;
    let mut mine = common.clone();
    let mut nonce = [0u8; 32];
    random_bytes(rng, &mut nonce)?;
    mine.extend(nonce);
    let theirs = if prover {
        send(channel, 1, &mine, audit)?;
        recv(channel, 2, 152, audit)?
    } else {
        let peer = recv(channel, 1, 152, audit)?;
        if peer[..120] != common {
            return Err(invalid("context mismatch"));
        }
        send(channel, 2, &mine, audit)?;
        peer
    };
    if theirs[..120] != common {
        return Err(invalid("context mismatch"));
    }
    let mut full = common;
    if prover {
        full.extend(&mine[120..]);
        full.extend(&theirs[120..]);
    } else {
        full.extend(&theirs[120..]);
        full.extend(&mine[120..]);
    }
    Ok(full)
}
fn encode_fields(rows: &[F9]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(rows.len() * 72));
    for row in rows {
        for x in row.0 {
            out.extend(x.to_le_bytes());
        }
    }
    out
}
fn decode_fields(data: &[u8]) -> Result<Zeroizing<Vec<F9>>> {
    if data.len() % 72 != 0 {
        return Err(invalid("Fp9 length"));
    }
    let mut rows = Zeroizing::new(vec![F9::default(); data.len() / 72]);
    for (out, raw) in rows.iter_mut().zip(data.chunks_exact(72)) {
        for (x, bytes) in out.0.iter_mut().zip(raw.chunks_exact(8)) {
            *x = u64::from_le_bytes(bytes.try_into().unwrap());
            if *x >= P {
                return Err(invalid("noncanonical Fp limb"));
            }
        }
    }
    Ok(rows)
}
fn bit(delta: &F9, i: usize) -> u8 {
    ((delta.0[i / 64] >> (i % 64)) & 1) as u8
}
fn prf(
    seed: &[u8; 32],
    context: &[u8],
    i: usize,
    j: u8,
    row: usize,
    work: &mut Work,
) -> Result<u64> {
    work.prf_field_outputs += 1;
    #[cfg(feature = "c71-b11")]
    if context.starts_with(b"C71B11v1") || context.starts_with(b"C71B12F1") {
        return aes_prf(seed, context, i, j, row, work);
    }
    let mut h = blake3::Hasher::new_keyed(seed);
    h.update(b"C71B9/COPE/sender/");
    h.update(context);
    h.update(&(i as u32).to_le_bytes());
    h.update(&[j]);
    h.update(&(row as u64).to_le_bytes());
    let mut reader = h.finalize_xof();
    sample_fp(
        |bytes| {
            reader.fill(bytes);
            Ok(())
        },
        work,
    )
}

#[cfg(feature = "c71-b11")]
fn aes_prf(
    seed: &[u8; 32],
    context: &[u8],
    i: usize,
    j: u8,
    row: usize,
    work: &mut Work,
) -> Result<u64> {
    use aes::{
        cipher::{Block, BlockEncrypt, KeyInit},
        Aes256,
    };
    let (rows, height, domain) = if context.starts_with(b"C71B12F1") {
        if context.len() != 184 {
            return Err(invalid("B12 fixed-run PRF context length"));
        }
        let n = u64::from_le_bytes(context[104..112].try_into().unwrap());
        if !(1..=MAX_FIXED_RUN_ROWS as u64).contains(&n) {
            return Err(invalid("B12 fixed-run PRF capacity"));
        }
        let rows = n as usize + 9;
        (rows, rows.next_power_of_two().ilog2(), b"C71B12/COPE/fixed-run/leaf/".as_slice())
    } else {
        (216, 8, b"C71B11/COPE/leaf/".as_slice())
    };
    if row >= rows || i >= OTS || j > 1 {
        return Err(invalid("B11 PRF domain exceeds admitted profile"));
    }
    // ponytail: recompute the bounded path; a cache needs its own erasure audit.
    let mut leaf = Zeroizing::new(*seed);
    for depth in (0..height).rev() {
        let cipher = Aes256::new_from_slice(&*leaf).unwrap();
        let mut blocks: [Block<Aes256>; 4] = Default::default();
        for (index, block) in blocks.iter_mut().enumerate() {
            block.copy_from_slice(&(index as u128).to_le_bytes());
        }
        cipher.encrypt_blocks(&mut blocks);
        let child = 2 * ((row >> depth) & 1); // public row, never an OT choice
        leaf[..16].copy_from_slice(&blocks[child]);
        leaf[16..].copy_from_slice(&blocks[child + 1]);
        for block in &mut blocks {
            block[..].zeroize();
        }
        work.aes_key_schedules += 1;
        work.aes_block_encryptions += 4;
        // RustCrypto's zeroize feature erases the round-key schedule on drop.
    }
    let mut h = Shake256::default();
    h.update(domain);
    h.update(context);
    h.update(&(i as u32).to_le_bytes());
    h.update(&[j]);
    h.update(&(row as u64).to_le_bytes());
    h.update(&*leaf);
    let mut reader = h.finalize_xof();
    sample_fp(
        |bytes| {
            XofReader::read(&mut reader, bytes);
            Ok(())
        },
        work,
    )
}

pub(super) fn mr19_sender(
    channel: &mut (impl Read + Write),
    context: &[u8],
    profile: Mr19Profile,
    rng: &mut (impl RngCore + CryptoRng),
    audit: &mut Audit,
) -> Result<Zeroizing<Vec<[[u8; 32]; 2]>>> {
    let point_bytes = profile
        .ot_count
        .checked_mul(2 * POINT_BYTES)
        .ok_or_else(|| invalid("MR19 profile overflow"))?;
    let seed_bytes =
        profile.ot_count.checked_mul(64).ok_or_else(|| invalid("MR19 profile overflow"))?;
    if profile.ot_count == 0 || profile.ot_count > OTS {
        return Err(invalid("MR19 profile outside supported OT envelope"));
    }
    let receiver = recv(channel, 3, point_bytes, audit)?;
    // Decode the entire first message before sampling any sender exponent.
    let points = receiver.chunks_exact(POINT_BYTES).map(decode).collect::<Result<Vec<_>>>()?;
    let mut seeds = Zeroizing::new(vec![[[0u8; 32]; 2]; profile.ot_count]);
    let mut responses = Vec::with_capacity(point_bytes);
    let mut ciphertexts = Zeroizing::new(Vec::with_capacity(seed_bytes));
    for i in 0..profile.ot_count {
        for j in 0..2 {
            let h = group_hash_for(
                profile.group_receiver_domain,
                context,
                i,
                j as u8,
                &points[2 * i + 1 - j],
                &mut audit.work,
            )?;
            audit.work.point_add += 1;
            let a_point = points[2 * i + j] + h;
            let a = scalar(rng, &mut audit.work)?;
            responses.extend(encode(&fixed(&a, &mut audit.work)));
            let z = variable(&a_point, &a, &mut audit.work);
            let pad = kdf_for(profile.seed_sender_domain, context, i, j as u8, &z, &mut audit.work);
            random_bytes(rng, &mut seeds[i][j])?;
            ciphertexts.extend(seeds[i][j].iter().zip(pad.iter()).map(|(a, b)| a ^ b));
        }
    }
    send(channel, 4, &responses, audit)?;
    send(channel, 5, &ciphertexts, audit)?;
    Ok(seeds)
}
fn ot_sender(
    channel: &mut (impl Read + Write),
    context: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
    audit: &mut Audit,
) -> Result<Zeroizing<Vec<[[u8; 32]; 2]>>> {
    mr19_sender(channel, context, LEGACY_MR19, rng, audit)
}
pub(super) fn mr19_receiver(
    channel: &mut (impl Read + Write),
    context: &[u8],
    profile: Mr19Profile,
    choice: impl Fn(usize) -> u8,
    rng: &mut (impl RngCore + CryptoRng),
    audit: &mut Audit,
) -> Result<Zeroizing<Vec<[u8; 32]>>> {
    let point_bytes = profile
        .ot_count
        .checked_mul(2 * POINT_BYTES)
        .ok_or_else(|| invalid("MR19 profile overflow"))?;
    let seed_bytes =
        profile.ot_count.checked_mul(64).ok_or_else(|| invalid("MR19 profile overflow"))?;
    if profile.ot_count == 0 || profile.ot_count > OTS {
        return Err(invalid("MR19 profile outside supported OT envelope"));
    }
    let mut scalars = Zeroizing::new(Vec::with_capacity(profile.ot_count));
    let mut choices = Zeroizing::new(Vec::with_capacity(profile.ot_count));
    let mut request = Vec::with_capacity(point_bytes);
    for i in 0..profile.ot_count {
        let c = choice(i);
        if c > 1 {
            return Err(invalid("MR19 choice is not a bit"));
        }
        choices.push(c);
        let choice = Choice::from(c);
        let b = scalar(rng, &mut audit.work)?;
        let t = scalar(rng, &mut audit.work)?;
        let other = fixed(&t, &mut audit.work);
        let h =
            group_hash_for(profile.group_receiver_domain, context, i, c, &other, &mut audit.work)?;
        audit.work.point_add += 1;
        let selected = fixed(&b, &mut audit.work) - h;
        // Balance the *other final public RO input* before exposing the message.
        // Total rejection work now depends on both final public inputs, not c.
        std::hint::black_box(group_hash_for(
            profile.group_receiver_domain,
            context,
            i,
            1 - c,
            &selected,
            &mut audit.work,
        )?);
        request.extend(encode(&Point::conditional_select(&selected, &other, choice)));
        request.extend(encode(&Point::conditional_select(&other, &selected, choice)));
        scalars.push(*b);
    }
    send(channel, 3, &request, audit)?;
    let response = recv(channel, 4, point_bytes, audit)?;
    // A malformed unselected branch must also abort, before any COPE output.
    let points = response.chunks_exact(POINT_BYTES).map(decode).collect::<Result<Vec<_>>>()?;
    let ciphertexts = recv(channel, 5, seed_bytes, audit)?;
    let mut seeds = Zeroizing::new(vec![[0u8; 32]; profile.ot_count]);
    for i in 0..profile.ot_count {
        let mut options = Zeroizing::new([[0u8; 32]; 2]);
        for j in 0..2 {
            let z = variable(&points[2 * i + j], &scalars[i], &mut audit.work);
            let pad = kdf_for(profile.seed_sender_domain, context, i, j as u8, &z, &mut audit.work);
            for k in 0..32 {
                options[j][k] = ciphertexts[(2 * i + j) * 32 + k] ^ pad[k];
            }
        }
        for k in 0..32 {
            seeds[i][k] =
                u8::conditional_select(&options[0][k], &options[1][k], Choice::from(choices[i]));
        }
    }
    Ok(seeds)
}
fn ot_receiver(
    channel: &mut (impl Read + Write),
    context: &[u8],
    delta: &F9,
    rng: &mut (impl RngCore + CryptoRng),
    audit: &mut Audit,
) -> Result<Zeroizing<Vec<[u8; 32]>>> {
    mr19_receiver(channel, context, LEGACY_MR19, |i| bit(delta, i), rng, audit)
}

/// Real OT/PRF prover role. Run once on a dedicated authenticated channel.
pub fn prover(channel: impl Read + Write, context: Context) -> Result<ProverOutput> {
    prover_for(channel, context, &mut OsRng, Suite::B9)
}
/// B11 intermediate AES profile, at most 207 data rows; component use only.
#[cfg(feature = "c71-b11")]
pub fn prover_aes(channel: impl Read + Write, context: Context) -> Result<ProverOutput> {
    prover_for(channel, context, &mut OsRng, Suite::B11)
}
/// B12 larger finite AES capacity, for ONE setup in an uninterrupted run.
/// Use through Lifetime::prover_fixed_run to enforce that scope and the seal.
#[cfg(feature = "c71-b11")]
pub(crate) fn prover_fixed_run(
    channel: impl Read + Write,
    context: Context,
) -> Result<ProverOutput> {
    prover_for(channel, context, &mut OsRng, Suite::B12FixedRun)
}
fn prover_for(
    mut channel: impl Read + Write,
    context: Context,
    rng: &mut (impl RngCore + CryptoRng),
    suite: Suite,
) -> Result<ProverOutput> {
    let mut audit = Audit::default();
    let start = Instant::now();
    let full = handshake(&mut channel, &context, true, rng, &mut audit, suite)?;
    let seeds = ot_sender(&mut channel, &full, rng, &mut audit)?;
    audit.phase("headers_and_OT", start);
    let start = Instant::now();
    let n = context.rows;
    let rows = n + 9;
    let mut values = Zeroizing::new(vec![0u64; rows]);
    let mut tags = Zeroizing::new(vec![F9::default(); rows]);
    // Same single frame and row order as B9/B11. Only its buffering changes:
    // V sends no challenge until the WHOLE COPE frame has arrived.
    send_header(&mut channel, 6, OTS * rows * 8)?;
    let mut corrections = Zeroizing::new(Vec::with_capacity(OTS * 8));
    for row in 0..rows {
        values[row] = sample_fp(|v| random_bytes(rng, v), &mut audit.work)?;
        for i in 0..OTS {
            let q0 = Fp::new(prf(&seeds[i][0], &full, i, 0, row, &mut audit.work)?);
            let q1 = Fp::new(prf(&seeds[i][1], &full, i, 1, row, &mut audit.work)?);
            corrections.extend((q0 - q1 - Fp::new(values[row])).value().to_le_bytes());
            audit.work.cope_gadget_products += 1;
            tags[row].0[i / 64] =
                (Fp::new(tags[row].0[i / 64]) + Fp::new(1u64 << (i % 64)) * q0).value();
        }
        channel.write_all(&corrections)?;
        corrections.zeroize();
    }
    drop(seeds);
    channel.flush()?;
    audit.sent_frames.push((6, OTS * rows * 8 + 9));
    drop(corrections);
    audit.phase("COPE", start);
    let start = Instant::now();
    let challenges = recv(&mut channel, 7, n * 72, &mut audit)?;
    let chi = decode_fields(&challenges)?;
    let mut x = Zeroizing::new(F9::default());
    let mut z = Zeroizing::new(F9::default());
    for i in 0..n {
        audit.work.check_base_products += 9;
        *x = x.add(chi[i].scale(values[i]));
        *z = z.add(chi[i].mul(tags[i], &mut audit.work));
    }
    for h in 0..9 {
        x.0[h] = (Fp::new(x.0[h]) + Fp::new(values[n + h])).value();
        *z = z.add(F9::basis(h).mul(tags[n + h], &mut audit.work));
    }
    send(&mut channel, 8, &encode_fields(&[*x, *z]), &mut audit)?;
    let compression = recv(&mut channel, 9, 72, &mut audit)?;
    let alpha = decode_fields(&compression)?;
    let out =
        Zeroizing::new(tags[..n].iter().map(|t| t.compress(&alpha, &mut audit.work)).collect());
    values[n..].zeroize();
    values.truncate(n);
    audit.phase("check_and_compression", start);
    Ok(ProverOutput { values, tags: out, audit })
}
/// Real OT/PRF verifier role; compression is sent only after the full Fp9 check.
pub fn verifier(channel: impl Read + Write, context: Context) -> Result<VerifierOutput> {
    verifier_for(channel, context, &mut OsRng, Suite::B9)
}
/// B11 intermediate verifier; fresh key and full Fp9 check on every execution.
#[cfg(feature = "c71-b11")]
pub fn verifier_aes(channel: impl Read + Write, context: Context) -> Result<VerifierOutput> {
    verifier_for(channel, context, &mut OsRng, Suite::B11)
}
#[cfg(feature = "c71-b11")]
pub(crate) fn verifier_fixed_run(
    channel: impl Read + Write,
    context: Context,
) -> Result<VerifierOutput> {
    verifier_for(channel, context, &mut OsRng, Suite::B12FixedRun)
}
fn verifier_for(
    mut channel: impl Read + Write,
    context: Context,
    rng: &mut (impl RngCore + CryptoRng),
    suite: Suite,
) -> Result<VerifierOutput> {
    let mut audit = Audit::default();
    let start = Instant::now();
    let full = handshake(&mut channel, &context, false, rng, &mut audit, suite)?;
    let delta = Zeroizing::new(random_f9(rng, &mut audit.work)?);
    let seeds = ot_receiver(&mut channel, &full, &delta, rng, &mut audit)?;
    audit.phase("headers_and_OT", start);
    let start = Instant::now();
    let n = context.rows;
    let rows = n + 9;
    recv_header(&mut channel, 6, OTS * rows * 8)?;
    let mut raw = Zeroizing::new(vec![0; OTS * 8]);
    let mut keys = Zeroizing::new(vec![F9::default(); rows]);
    for row in 0..rows {
        channel.read_exact(&mut raw)?;
        for i in 0..OTS {
            let offset = i * 8;
            let d = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
            if d >= P {
                return Err(invalid("noncanonical COPE correction"));
            }
            let c = bit(&delta, i);
            let q = Fp::new(prf(&seeds[i], &full, i, c, row, &mut audit.work)?);
            // No secret-dependent branch or multiplication count for the choice.
            let correction = u64::conditional_select(&0, &d, Choice::from(c));
            audit.work.cope_gadget_products += 1;
            keys[row].0[i / 64] = (Fp::new(keys[row].0[i / 64])
                + Fp::new(1u64 << (i % 64)) * (q + Fp::new(correction)))
            .value();
        }
    }
    audit.received_frames.push((6, OTS * rows * 8 + 9));
    drop(raw);
    drop(seeds);
    audit.phase("COPE", start);
    let start = Instant::now();
    let mut chi = Zeroizing::new(Vec::with_capacity(n));
    for _ in 0..n {
        chi.push(random_f9(rng, &mut audit.work)?);
    }
    send(&mut channel, 7, &encode_fields(&chi), &mut audit)?;
    let response = recv(&mut channel, 8, 144, &mut audit)?;
    let xz = decode_fields(&response)?;
    let mut y = Zeroizing::new(F9::default());
    for i in 0..n {
        *y = y.add(chi[i].mul(keys[i], &mut audit.work));
    }
    for h in 0..9 {
        *y = y.add(F9::basis(h).mul(keys[n + h], &mut audit.work));
    }
    let expected = Zeroizing::new(y.add(delta.mul(xz[0], &mut audit.work)));
    if !bool::from(expected.0.ct_eq(&xz[1].0)) {
        return Err(invalid("Fp9 correlation check"));
    }
    // Fresh compression only after acceptance; a zero key burns this execution.
    let alpha = Zeroizing::new(vec![random_f9(rng, &mut audit.work)?]);
    let compressed = Zeroizing::new(delta.compress(&alpha, &mut audit.work));
    if bool::from(compressed.ct_eq(&[0u64; 3])) {
        return Err(invalid("zero compressed key"));
    }
    send(&mut channel, 9, &encode_fields(&alpha), &mut audit)?;
    let out =
        Zeroizing::new(keys[..n].iter().map(|v| v.compress(&alpha, &mut audit.work)).collect());
    audit.phase("check_and_compression", start);
    Ok(VerifierOutput { delta: compressed, keys: out, audit })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::io::Cursor;

    #[test]
    #[cfg(feature = "c71-b11")]
    fn c71_b11_aes_independent_vectors_and_profile_boundary() {
        // Computed independently with OpenSSL aes-256-ecb and Python SHAKE256.
        let seed = std::array::from_fn(|i| i as u8);
        let mut work = Work::default();
        for (row, expected) in
            [(0, 27390695000489068), (1, 15138967911530661982), (215, 12348729350428255245)]
        {
            assert_eq!(aes_prf(&seed, b"C71B11v1-kat", 17, 1, row, &mut work).unwrap(), expected);
        }
        assert_eq!((work.aes_key_schedules, work.aes_block_encryptions), (24, 96));
        assert!(aes_prf(&seed, b"C71B11v1-kat", 17, 1, 216, &mut work).is_err());
        let mut c = context();
        c.rows = 207;
        assert_ne!(c.common().unwrap(), c.common_for(Suite::B11).unwrap());
        c.rows = 208;
        assert!(c.common_for(Suite::B11).is_err());
        assert!(c.common().is_ok());
        let mut header = context().common().unwrap();
        header.extend([0; 32]);
        assert!(handshake(
            &mut tape(wire(1, &header)),
            &context(),
            false,
            &mut ConstantRng(0),
            &mut Audit::default(),
            Suite::B11
        )
        .is_err());
    }

    #[test]
    #[cfg(feature = "c71-b11")]
    fn c71_b12_fixed_run_aes_paths_and_domain_boundary() {
        // Independent OpenSSL AES-256-ECB + Python hashlib SHAKE256 vectors.
        // Only four paths: the largest capacity is never materialized here.
        let seed = std::array::from_fn(|i| i as u8);
        let mut work = Work::default();
        for (n, row, expected) in [
            (258, 0, 4059061014208010961),
            (258, 256, 6589163169525333170),
            (108201, 108209, 3263907683622810295),
            (MAX_FIXED_RUN_ROWS, (1 << 24) - 1, 3120825137042157991),
        ] {
            let mut c = context();
            c.rows = n;
            let mut full = c.common_for(Suite::B12FixedRun).unwrap();
            full.extend([4; 32]);
            full.extend([5; 32]);
            assert_eq!(aes_prf(&seed, &full, 17, 1, row, &mut work).unwrap(), expected);
            assert!(aes_prf(&seed, &full, 17, 1, n + 9, &mut work).is_err());
            assert!(aes_prf(&seed, &full[..183], 17, 1, 0, &mut work).is_err());
        }
        assert_eq!(work.aes_key_schedules, 9 + 9 + 17 + 24);
        assert_eq!(work.aes_block_encryptions, 4 * (9 + 9 + 17 + 24));
        let mut c = context();
        c.rows = MAX_FIXED_RUN_ROWS + 1;
        assert!(c.common_for(Suite::B12FixedRun).is_err());
        let mut header = context().common_for(Suite::B11).unwrap();
        header.extend([0; 32]);
        assert!(handshake(
            &mut tape(wire(1, &header)),
            &context(),
            false,
            &mut ConstantRng(0),
            &mut Audit::default(),
            Suite::B12FixedRun
        )
        .is_err());
        check_zero_key(Suite::B12FixedRun);
    }

    fn hex(raw: &[u8]) -> String {
        raw.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn context() -> Context {
        Context { session: [1; 32], channel: [2; 32], capacity: [3; 32], rows: 3 }
    }
    fn wire(tag: u8, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        send(&mut out, tag, raw, &mut Audit::default()).unwrap();
        out
    }
    struct Tape {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Tape {
        fn read(&mut self, b: &mut [u8]) -> Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Tape {
        fn write(&mut self, b: &[u8]) -> Result<usize> {
            self.output.extend(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
    fn tape(input: Vec<u8>) -> Tape {
        Tape { input: Cursor::new(input), output: Vec::new() }
    }

    struct ConstantRng(u8);
    impl CryptoRng for ConstantRng {}
    impl RngCore for ConstantRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.0; 4])
        }
        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.0; 8])
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(self.0);
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.fill_bytes(out);
            Ok(())
        }
    }

    #[test]
    fn c71_b9_canonical_codec_rng_and_independent_python_vectors() {
        let mut w = Work::default();
        let g = Point::GENERATOR;
        assert_eq!(decode(&encode(&g)).unwrap(), g);
        assert_eq!(decode(&[0; 67]).unwrap(), Point::IDENTITY);
        let mut bad = encode(&g);
        bad[0] = 4;
        assert!(decode(&bad).is_err());
        bad[0] = 2;
        bad[1..].fill(255);
        assert!(decode(&bad).is_err());
        bad[1] = 1; // x = 2^521-1 is outside the P-521 coordinate field
        assert!(decode(&bad).is_err());
        bad.fill(0);
        bad[0] = 2;
        bad[66] = 3; // x=3 is off curve for either sign
        assert!(decode(&bad).is_err());
        bad[0] = 3;
        assert!(decode(&bad).is_err());
        bad[0] = 0; // identity must be exactly 67 zero bytes
        assert!(decode(&bad).is_err());
        for raw in [vec![], vec![0; 66], vec![0; 68], vec![1; 67]] {
            assert!(decode(&raw).is_err());
        }
        let mut raw = vec![0; 72];
        raw[..8].copy_from_slice(&P.to_le_bytes());
        assert!(decode_fields(&raw).is_err());
        assert!(decode_fields(&raw[..71]).is_err());
        assert!(recv(&mut Cursor::new(wire(4, &[0; 9])), 3, 9, &mut Audit::default()).is_err());
        assert!(recv(
            &mut Cursor::new([3u8].into_iter().chain(u64::MAX.to_le_bytes()).collect::<Vec<_>>()),
            3,
            9,
            &mut Audit::default()
        )
        .is_err());
        assert!(recv(
            &mut Cursor::new(wire(3, &[0; 9])[..12].to_vec()),
            3,
            9,
            &mut Audit::default()
        )
        .is_err());
        let ctx = b"native-source-vector";
        let h = group_hash(ctx, 17, 1, &g, &mut w).unwrap();
        assert_eq!(hex(&encode(&h)), "0201d6ff4beab451430d54a88b7601ba34efe9d84d0406e74704e7bd367c54ede0f00d51a1f864a7f317c4dbdee5355f0513aabfd12fa97ecbebcc64815a6b559e915e");
        assert_eq!(
            hex(&*kdf(ctx, 17, 1, &g, &mut w)),
            "06893ac0862d2f3bc2241c8222de51d9f45b65d70e73ac762081df0a2c0d1347"
        );
        for (ctx2, i, j) in
            [(b"other-context".as_slice(), 17, 1), (ctx.as_slice(), 18, 1), (ctx.as_slice(), 17, 0)]
        {
            assert_ne!(group_hash(ctx2, i, j, &g, &mut w).unwrap(), h);
        }
        let before = w.field_candidates;
        assert_eq!(
            sample_fp(
                |v| {
                    v.fill(0);
                    Ok(())
                },
                &mut w
            )
            .unwrap(),
            0
        );
        assert_eq!(w.field_candidates - before, 8);
        assert!(sample_fp(
            |v| {
                v.fill(255);
                Ok(())
            },
            &mut w
        )
        .is_err());
        let mut draw = 0;
        assert_eq!(
            sample_fp(
                |v| {
                    draw += 1;
                    v.copy_from_slice(&(if draw == 2 { 7u64 } else { P }).to_le_bytes());
                    Ok(())
                },
                &mut w
            )
            .unwrap(),
            7
        );
        assert_eq!(draw, 8);
        assert_eq!(*scalar(&mut ConstantRng(0), &mut w).unwrap(), Scalar::ZERO);
        assert!(scalar(&mut ConstantRng(255), &mut w).is_err());
        let mut c = context();
        c.rows = usize::MAX;
        assert!(c.common().is_err());
        let mut rng = StdRng::seed_from_u64(13);
        let mut c = context();
        c.channel = [9; 32];
        let mut header = c.common().unwrap();
        header.extend([0; 32]);
        assert!(handshake(
            &mut tape(wire(1, &header)),
            &context(),
            false,
            &mut rng,
            &mut Audit::default(),
            Suite::B9
        )
        .is_err());
    }

    #[test]
    fn c71_b9_fp9_source_equations_and_all_mask_coordinates() {
        let mut w = Work::default();
        let mut rng = StdRng::seed_from_u64(99);
        let d = random_f9(&mut rng, &mut w).unwrap();
        let alpha = [random_f9(&mut rng, &mut w).unwrap()];
        let k = random_f9(&mut rng, &mut w).unwrap();
        let u = P - 7;
        let tag = k.add(d.scale(u));
        assert_eq!(
            fp3(tag.compress(&alpha, &mut w)),
            fp3(k.compress(&alpha, &mut w)) + fp3(d.compress(&alpha, &mut w)).mul_base(Fp::new(u))
        );
        for i in 0..9 {
            for j in 0..9 {
                let expected = F9::basis((i + j) % 9).scale(if i + j >= 9 { 2 } else { 1 });
                assert_eq!(F9::basis(i).mul(F9::basis(j), &mut w), expected);
            }
        }
        let x = random_f9(&mut rng, &mut w).unwrap();
        let y = random_f9(&mut rng, &mut w).unwrap();
        let z = y.add(d.mul(x, &mut w));
        for h in 0..9 {
            let shifted = x.add(F9::basis(h));
            assert_eq!(y.add(d.mul(shifted, &mut w)), z.add(d.mul(F9::basis(h), &mut w)));
        }
        // Malicious-verifier choices, including Delta=0, do not remove masks.
        for d in [F9::default(), F9::basis(8)] {
            for h in 0..9 {
                let adversarial_chi = F9::basis(h);
                let response_x = x.add(adversarial_chi.scale(u));
                let simulated_z = y.add(d.mul(response_x, &mut w));
                assert_eq!(
                    simulated_z,
                    y.add(d.mul(x, &mut w)).add(d.mul(adversarial_chi.scale(u), &mut w))
                );
            }
        }
    }

    #[test]
    fn c71_b9_receiver_decodes_both_branches_and_sender_waits() {
        // No peer thread: these malicious peers supply prerecorded byte frames.
        let mut rng = StdRng::seed_from_u64(77);
        let mut points = vec![0u8; OTS * 2 * POINT_BYTES];
        points[POINT_BYTES] = 4; // invalid branch 1, even when every choice is 0
        let mut input = wire(4, &points);
        input.extend(wire(5, &vec![0; OTS * 64]));
        let mut a = Audit::default();
        assert!(ot_receiver(
            &mut tape(input),
            b"malicious-sender",
            &F9::default(),
            &mut rng,
            &mut a
        )
        .is_err());
        assert_eq!(a.work.variable_scalar_mul, 0);
        assert_eq!(a.work.kdf, 0);
        let mut a = Audit::default();
        assert!(ot_sender(&mut tape(wire(3, &points)), b"malicious-receiver", &mut rng, &mut a)
            .is_err());
        assert_eq!(a.work.scalar_candidates, 0);
        assert!(a.sent_frames.is_empty());
    }

    #[test]
    fn c71_b9_ot_choices_identity_sender_and_cross_context_relay() {
        // Native two-branch MR19 equations with full-width deterministic test coins.
        let ctx = b"source-equations";
        let mut w = Work::default();
        let mut rng = StdRng::seed_from_u64(123);
        for c in 0..2 {
            let b = scalar(&mut rng, &mut w).unwrap();
            let t = scalar(&mut rng, &mut w).unwrap();
            let other = fixed(&t, &mut w);
            let h = group_hash(ctx, 0, c, &other, &mut w).unwrap();
            let mut r = [other; 2];
            r[c as usize] = fixed(&b, &mut w) - h;
            for j in 0..2 {
                let a = scalar(&mut rng, &mut w).unwrap();
                let ap = r[j] + group_hash(ctx, 0, j as u8, &r[1 - j], &mut w).unwrap();
                let z = variable(&ap, &a, &mut w);
                if j == c as usize {
                    let received = variable(&fixed(&a, &mut w), &b, &mut w);
                    assert_eq!(*z, *received);
                    assert_eq!(*kdf(ctx, 0, c, &z, &mut w), *kdf(ctx, 0, c, &received, &mut w));
                    let relay_ap = r[j]
                        + group_hash(b"different-channel", 0, j as u8, &r[1 - j], &mut w).unwrap();
                    assert_ne!(*variable(&relay_ap, &a, &mut w), *received);
                }
            }
        }
        // A malicious sender may legally send identities. This is still OT,
        // with chosen inputs determined by its ciphertexts, not a codec error.
        let mut input = wire(4, &vec![0; OTS * 2 * POINT_BYTES]);
        input.extend(wire(5, &vec![0; OTS * 64]));
        let mut a = Audit::default();
        let seeds = ot_receiver(&mut tape(input), ctx, &F9::default(), &mut rng, &mut a).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            assert_eq!(*seed, *kdf(ctx, i, 0, &Point::IDENTITY, &mut w));
        }
        assert_eq!(a.work.variable_scalar_mul, (2 * OTS) as u64);
        assert_eq!(a.work.kdf, (2 * OTS) as u64);
        assert_eq!(a.work.group_hash, (2 * OTS) as u64);
    }

    #[test]
    fn c71_b9_zero_compressed_key_withholds_last_frame() {
        check_zero_key(Suite::B9);
    }

    #[test]
    #[cfg(feature = "c71-b11")]
    fn c71_b11_zero_compressed_key_withholds_last_frame() {
        check_zero_key(Suite::B11);
    }

    fn check_zero_key(suite: Suite) {
        // Drive the whole verifier with known test-only zero coins. Delta=0,
        // B0=B1=identity and zero ciphertexts make its selected PRF seed known.
        let c = context();
        let mut header = c.common_for(suite).unwrap();
        header.extend([7u8; 32]);
        let mut full = c.common_for(suite).unwrap();
        full.extend([7u8; 32]);
        full.extend([0u8; 32]);
        let mut w = Work::default();
        let mut z = F9::default();
        for h in 0..9 {
            let mut key = F9::default();
            for i in 0..OTS {
                let seed = kdf(&full, i, 0, &Point::IDENTITY, &mut w);
                let q = prf(&seed, &full, i, 0, c.rows + h, &mut w).unwrap();
                key.0[i / 64] =
                    (Fp::new(key.0[i / 64]) + Fp::new(1u64 << (i % 64)) * Fp::new(q)).value();
            }
            z = z.add(F9::basis(h).mul(key, &mut w));
        }
        let mut input = wire(1, &header);
        input.extend(wire(4, &vec![0; OTS * 2 * POINT_BYTES]));
        input.extend(wire(5, &vec![0; OTS * 64]));
        input.extend(wire(6, &vec![0; OTS * (c.rows + 9) * 8]));
        input.extend(wire(8, &encode_fields(&[F9::default(), z])));
        let mut channel = tape(input);
        let error = verifier_for(&mut channel, c, &mut ConstantRng(0), suite).err().unwrap();
        assert_eq!(error.to_string(), "zero compressed key");
        let mut sent = &channel.output[..];
        let mut tags = Vec::new();
        while !sent.is_empty() {
            let len = u64::from_le_bytes(sent[1..9].try_into().unwrap()) as usize;
            tags.push(sent[0]);
            sent = &sent[9 + len..];
        }
        assert_eq!(tags, [2, 3, 7]); // no compression/output and no retry
    }
}

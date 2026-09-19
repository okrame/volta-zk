//! Reduced, test-only REAL384OT -> AES-COPE -> Seed6 adapter.
//!
//! This is not a production entry point.  Durable one-use sealing, the cGGM
//! guard-before-c, opposite-role F_EQ orchestration and transport ownership
//! remain with the outer bootstrap lifetime.

use super::{
    compress_prover, compress_verifier, verify_relation, Checked, Fp3Words, ProverCheck, Seed6Work,
    VerifierCheck, K6, MASKS, MR19,
};
use crate::c71_bootstrap::{
    aes_prf_for_profile, handshake, mr19_receiver, mr19_sender, random_bytes, recv, recv_header,
    sample_fp, send, send_header, AesPrfProfile, Audit, Context, Suite,
};
use p521::elliptic_curve::subtle::{Choice, ConditionallySelectable};
use rand::{CryptoRng, RngCore};
use std::io::{self, Read, Write};
use volta_field::Fp;
use zeroize::{Zeroize, Zeroizing};

const OTS: usize = 384;
const CORRECTION_ROW_BYTES: usize = OTS * 8;
const AES_DOMAIN: &[u8] = b"C71S6/COPE/fixed-run/leaf/v1/";

type Result<T> = io::Result<T>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checked_rows(n: usize) -> Result<usize> {
    if n == 0 {
        return Err(invalid("Seed6 needs at least one returned row"));
    }
    n.checked_add(MASKS)
        .filter(|rows| rows.checked_mul(CORRECTION_ROW_BYTES).is_some())
        .ok_or_else(|| invalid("Seed6 row count overflow"))
}

fn random_k6(rng: &mut (impl RngCore + CryptoRng), audit: &mut Audit) -> Result<K6> {
    let mut limbs = Zeroizing::new([0u64; 6]);
    for limb in limbs.iter_mut() {
        *limb = sample_fp(|bytes| random_bytes(rng, bytes), &mut audit.work)?;
    }
    Ok(K6(*limbs))
}

fn decode_k6(bytes: &[u8]) -> Result<K6> {
    K6::decode(bytes).map_err(|_| invalid("noncanonical Seed6 K6 encoding"))
}

fn delta_bit(delta: K6, index: usize) -> u8 {
    ((delta.0[index / 64] >> (index % 64)) & 1) as u8
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct NamedCapacities {
    /// Logical bytes in the suite-specific public common context.
    pub common_context_len: usize,
    /// Capacity of the retained common+two-nonce PRF context.
    pub full_context_capacity: usize,
    /// Maximum named `Vec` payload capacity after MR19 has returned.
    pub cope_phase: usize,
    /// Maximum named `Vec` payload capacity during the K6 check.
    pub check_phase: usize,
    /// Maximum named `Vec` payload capacity while producing compressed output.
    pub compression_phase: usize,
    /// Explicit non-heap K6/check/codec state, excluding compiler stack spills.
    pub check_named_state_bytes: usize,
    pub compression_named_state_bytes: usize,
    /// MR19 internal Vec bodies plus caller context/Delta; no allocator/stack.
    pub mr19_phase: usize,
    /// Returned allocation capacity only.
    pub retained_output: usize,
}

/// Output local to the party playing the authenticated-value/OT-sender role.
pub(super) struct RealProverOutput {
    pub values: Zeroizing<Vec<u64>>,
    pub tags: Zeroizing<Vec<Fp3Words>>,
    pub audit: Audit,
    pub seed6_work: Seed6Work,
    pub capacities: NamedCapacities,
}

/// Output local to the party holding Delta and playing the OT-receiver role.
pub(super) struct RealVerifierOutput {
    pub delta: Zeroizing<Fp3Words>,
    pub keys: Zeroizing<Vec<Fp3Words>>,
    pub audit: Audit,
    pub seed6_work: Seed6Work,
    pub capacities: NamedCapacities,
}

/// Test-only real prover role. `direction` is 0 for the main seed and 1 for
/// the opposite-role seed and is transcript-bound by `Suite::Seed6`.
pub(super) fn prover_with_rng(
    mut channel: impl Read + Write,
    context: Context,
    direction: u8,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RealProverOutput> {
    if direction > 1 {
        return Err(invalid("invalid Seed6 direction"));
    }
    let n = context.rows;
    let rows = checked_rows(n)?;
    let mut audit = Audit::default();
    let full = handshake(&mut channel, &context, true, rng, &mut audit, Suite::Seed6(direction))?;
    let full_context_capacity = full.capacity();
    let seeds = mr19_sender(&mut channel, &full, MR19, rng, &mut audit)?;
    if seeds.len() != OTS {
        return Err(invalid("Seed6 MR19 seed count"));
    }
    let profile = AesPrfProfile { rows, ot_count: OTS, domain: AES_DOMAIN };
    let mut values = Zeroizing::new(vec![0u64; rows]);
    let mut tags = Zeroizing::new(vec![K6::ZERO; rows]);
    let mut correction = Zeroizing::new(Vec::with_capacity(CORRECTION_ROW_BYTES));
    let mut capacities = NamedCapacities {
        common_context_len: 121,
        full_context_capacity,
        mr19_phase: audit.mr19_inner_vec_capacity_peak_bytes + full_context_capacity,
        ..NamedCapacities::default()
    };
    capacities.cope_phase = seeds.capacity() * 64
        + full.capacity()
        + values.capacity() * core::mem::size_of::<u64>()
        + tags.capacity() * core::mem::size_of::<K6>()
        + correction.capacity();

    send_header(&mut channel, 6, rows * CORRECTION_ROW_BYTES)?;
    for row in 0..rows {
        values[row] = sample_fp(|bytes| random_bytes(rng, bytes), &mut audit.work)?;
        let value = Fp::new(values[row]);
        let mut limbs = Zeroizing::new([0u64; 6]);
        correction.clear();
        for i in 0..OTS {
            audit.work.prf_field_outputs += 2;
            let q0 = Fp::new(aes_prf_for_profile(
                &seeds[i][0],
                &full,
                i,
                0,
                row,
                profile,
                &mut audit.work,
            )?);
            let q1 = Fp::new(aes_prf_for_profile(
                &seeds[i][1],
                &full,
                i,
                1,
                row,
                profile,
                &mut audit.work,
            )?);
            correction.extend((q0 - q1 - value).value().to_le_bytes());
            limbs[i / 64] = (Fp::new(limbs[i / 64]) + Fp::new(1u64 << (i % 64)) * q0).value();
            audit.work.cope_gadget_products += 1;
        }
        tags[row] = K6(*limbs);
        channel.write_all(&correction)?;
        correction.zeroize();
    }
    channel.flush()?;
    audit.sent_frames.push((6, rows * CORRECTION_ROW_BYTES + 9));
    drop(correction);
    drop(seeds);
    drop(full);

    recv_header(&mut channel, 7, n * 48)?;
    let mut check = ProverCheck::new();
    let mut encoded = Zeroizing::new([0u8; 48]);
    for row in 0..n {
        channel.read_exact(&mut encoded[..])?;
        let chi = decode_k6(&encoded[..])?;
        check.absorb(chi, Fp::new(values[row]), tags[row]);
    }
    audit.received_frames.push((7, n * 48 + 9));
    for h in 0..MASKS {
        check.absorb(K6::basis(h), Fp::new(values[n + h]), tags[n + h]);
    }
    capacities.check_phase = values.capacity() * 8 + tags.capacity() * core::mem::size_of::<K6>();
    capacities.check_named_state_bytes = core::mem::size_of::<ProverCheck>() + 48 + 96;
    let mut response = Zeroizing::new([0u8; 96]);
    response[..48].copy_from_slice(&check.x.encode());
    response[48..].copy_from_slice(&check.z.encode());
    send(&mut channel, 8, &response[..], &mut audit)?;

    drop(check);
    drop(encoded);
    drop(response);
    // The honest verifier sends alpha after acceptance. A malicious verifier
    // may send arbitrary canonical alpha; the prover has no `Checked` token.
    let alpha_bytes = recv(&mut channel, 9, 48, &mut audit)?;
    capacities.check_phase = capacities
        .check_phase
        .max(values.capacity() * 8 + tags.capacity() * 48 + alpha_bytes.capacity());
    let alpha = decode_k6(&alpha_bytes[..])?.parts();
    drop(alpha_bytes);
    values[n..].zeroize();
    tags[n..].iter_mut().for_each(Zeroize::zeroize);
    let compressed = compress_prover(&tags[..n], alpha);
    capacities.compression_phase = values.capacity() * 8
        + tags.capacity() * core::mem::size_of::<K6>()
        + compressed.capacity() * core::mem::size_of::<Fp3Words>();
    capacities.compression_named_state_bytes = 48; // alpha
    values.truncate(n); // capacity still includes six erased mask slots
    tags.zeroize();
    drop(tags);
    capacities.retained_output =
        values.capacity() * 8 + compressed.capacity() * core::mem::size_of::<Fp3Words>();
    Ok(RealProverOutput {
        values,
        tags: compressed,
        audit,
        seed6_work: Seed6Work::for_rows(n),
        capacities,
    })
}

/// Test-only real verifier role. It sends no challenge before the entire COPE
/// correction frame has been received and validated.
pub(super) fn verifier_with_rng(
    mut channel: impl Read + Write,
    context: Context,
    direction: u8,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RealVerifierOutput> {
    if direction > 1 {
        return Err(invalid("invalid Seed6 direction"));
    }
    let n = context.rows;
    let rows = checked_rows(n)?;
    let mut audit = Audit::default();
    let full = handshake(&mut channel, &context, false, rng, &mut audit, Suite::Seed6(direction))?;
    let full_context_capacity = full.capacity();
    let delta = Zeroizing::new(random_k6(rng, &mut audit)?);
    let seeds =
        mr19_receiver(&mut channel, &full, MR19, |i| delta_bit(*delta, i), rng, &mut audit)?;
    if seeds.len() != OTS {
        return Err(invalid("Seed6 MR19 seed count"));
    }
    let profile = AesPrfProfile { rows, ot_count: OTS, domain: AES_DOMAIN };
    recv_header(&mut channel, 6, rows * CORRECTION_ROW_BYTES)?;
    let mut raw = Zeroizing::new(vec![0u8; CORRECTION_ROW_BYTES]);
    let mut keys = Zeroizing::new(vec![K6::ZERO; rows]);
    let mut capacities = NamedCapacities {
        common_context_len: 121,
        full_context_capacity,
        mr19_phase: audit.mr19_inner_vec_capacity_peak_bytes + full_context_capacity,
        ..NamedCapacities::default()
    };
    capacities.cope_phase = seeds.capacity() * 32
        + full.capacity()
        + raw.capacity()
        + keys.capacity() * core::mem::size_of::<K6>();
    for row in 0..rows {
        channel.read_exact(&mut raw[..])?;
        let mut limbs = Zeroizing::new([0u64; 6]);
        for i in 0..OTS {
            let offset = i * 8;
            let d = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
            if d >= volta_field::P {
                return Err(invalid("noncanonical Seed6 COPE correction"));
            }
            let choice = delta_bit(*delta, i);
            audit.work.prf_field_outputs += 1;
            let q = Fp::new(aes_prf_for_profile(
                &seeds[i],
                &full,
                i,
                choice,
                row,
                profile,
                &mut audit.work,
            )?);
            let selected = u64::conditional_select(&0, &d, Choice::from(choice));
            limbs[i / 64] = (Fp::new(limbs[i / 64])
                + Fp::new(1u64 << (i % 64)) * (q + Fp::new(selected)))
            .value();
            audit.work.cope_gadget_products += 1;
        }
        keys[row] = K6(*limbs);
    }
    audit.received_frames.push((6, rows * CORRECTION_ROW_BYTES + 9));
    raw.zeroize();
    drop(raw);
    drop(seeds);
    drop(full);

    let mut check = VerifierCheck::new();
    send_header(&mut channel, 7, n * 48)?;
    for row in 0..n {
        let chi = random_k6(rng, &mut audit)?;
        channel.write_all(&chi.encode())?;
        check.absorb(chi, keys[row]);
    }
    channel.flush()?;
    audit.sent_frames.push((7, n * 48 + 9));
    for h in 0..MASKS {
        check.absorb(K6::basis(h), keys[n + h]);
    }
    let response = recv(&mut channel, 8, 96, &mut audit)?;
    capacities.check_phase = keys.capacity() * 48 + response.capacity();
    capacities.check_named_state_bytes = 48 + 48 + 96; // Delta, Y, X/Z
    let prover = ProverCheck {
        x: Zeroizing::new(decode_k6(&response[..48])?),
        z: Zeroizing::new(decode_k6(&response[48..])?),
    };
    let checked: Checked = verify_relation(*delta, &prover, &check)
        .map_err(|_| invalid("Seed6 K6 correlation check"))?;
    drop(prover);
    drop(check);
    drop(response);
    keys[n..].iter_mut().for_each(Zeroize::zeroize);
    // Sampling happens strictly after relation acceptance.
    let alpha = random_k6(rng, &mut audit)?.parts();
    let alpha_wire = K6::new(alpha[0], alpha[1]).encode();
    let (compressed_delta, compressed_keys) =
        compress_verifier(&checked, *delta, &keys[..n], alpha)
            .map_err(|_| invalid("zero compressed Seed6 key"))?;
    send(&mut channel, 9, &alpha_wire, &mut audit)?;
    capacities.compression_phase = keys.capacity() * core::mem::size_of::<K6>()
        + compressed_keys.capacity() * core::mem::size_of::<Fp3Words>();
    capacities.compression_named_state_bytes = 48 + 48 + 48 + 24; // Delta, alpha, wire, delta
    drop(delta);
    keys.zeroize();
    drop(keys);
    capacities.retained_output = compressed_keys.capacity() * core::mem::size_of::<Fp3Words>();
    Ok(RealVerifierOutput {
        delta: compressed_delta,
        keys: compressed_keys,
        audit,
        seed6_work: Seed6Work::for_rows(n),
        capacities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{os::unix::net::UnixStream, thread, time::Duration};

    fn context(n: usize, direction: u8) -> Context {
        Context {
            session: [0x31 + direction; 32],
            channel: [0x51 + direction; 32],
            capacity: [0x71 + direction; 32],
            rows: n,
        }
    }

    // Private fixture recording: transcripts never escape this reduced test.
    struct Tape<T> {
        inner: T,
        read: Vec<u8>,
        written: Vec<u8>,
    }
    impl<T: Read> Read for Tape<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let n = self.inner.read(buf)?;
            self.read.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }
    impl<T> Write for Tape<T> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
    // Record incoming messages while forwarding real socket writes.
    struct LiveTape(Tape<UnixStream>);
    impl Read for LiveTape {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for LiveTape {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.inner.write(buf)
        }
        fn flush(&mut self) -> Result<()> {
            self.0.inner.flush()
        }
    }
    fn frames(wire: &[u8]) -> Vec<(u8, usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < wire.len() {
            let size = u64::from_le_bytes(wire[pos + 1..pos + 9].try_into().unwrap()) as usize;
            out.push((wire[pos], pos + 9, size));
            pos += 9 + size;
        }
        assert_eq!(pos, wire.len());
        out
    }

    fn run(n: usize, direction: u8, swap_physical_endpoints: bool) -> Vec<u8> {
        let (left, right) = UnixStream::pair().unwrap();
        for socket in [&left, &right] {
            socket.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let (prover_socket, verifier_socket) =
            if swap_physical_endpoints { (right, left) } else { (left, right) };
        let prover = thread::spawn(move || {
            prover_with_rng(
                prover_socket,
                context(n, direction),
                direction,
                &mut StdRng::seed_from_u64(0x5100 + direction as u64),
            )
            .unwrap()
        });
        let mut tape =
            LiveTape(Tape { inner: verifier_socket, read: Vec::new(), written: Vec::new() });
        let verifier = verifier_with_rng(
            &mut tape,
            context(n, direction),
            direction,
            &mut StdRng::seed_from_u64(0x6100 + direction as u64),
        )
        .unwrap();
        let prover = prover.join().unwrap();
        assert_eq!(prover.values.len(), n);
        assert_eq!(prover.tags.len(), n);
        assert_eq!(verifier.keys.len(), n);
        assert_eq!(prover.seed6_work, Seed6Work::for_rows(n));
        assert_eq!(verifier.seed6_work, Seed6Work::for_rows(n));
        let rows = (n + 6) as u64;
        let height = (n + 6).next_power_of_two().ilog2() as u64;
        for (party, factor) in [(&prover.audit, 2), (&verifier.audit, 1)] {
            assert_eq!(party.work.prf_field_outputs, factor * 384 * rows);
            assert_eq!(party.work.aes_key_schedules, factor * 384 * rows * height);
            assert_eq!(party.work.aes_block_encryptions, factor * 384 * rows * height * 4);
            assert_eq!(party.work.cope_gadget_products, 384 * rows);
        }
        assert_eq!(prover.audit.sent_frames, verifier.audit.received_frames);
        assert_eq!(verifier.audit.sent_frames, prover.audit.received_frames);
        assert_eq!(
            prover
                .audit
                .sent_frames
                .iter()
                .chain(verifier.audit.sent_frames.iter())
                .map(|(_, n)| n)
                .sum::<usize>(),
            127_515 + 324 + 3072 * (n + 6) + 48 * n + 96 + 48 + 36
        );
        assert_eq!(prover.capacities.retained_output, 8 * (n + 6) + 24 * n);
        assert_eq!(verifier.capacities.retained_output, 24 * n);
        println!(
            "seed6_real {}",
            serde_json::json!({
                "n": n, "direction": direction, "prover": prover.audit, "verifier": verifier.audit,
                "prover_capacities": prover.capacities, "verifier_capacities": verifier.capacities,
                "physical_peak_credit": false, "outer_composition_credit": false,
            })
        );
        for row in 0..n {
            let expected = verifier.keys[row].fp3()
                + verifier.delta.fp3().mul_base(Fp::new(prover.values[row]));
            assert_eq!(prover.tags[row].fp3(), expected);
        }
        tape.0.read
    }

    #[test]
    fn real_seed6_main_n1_and_inverse_n3_with_swapped_endpoints() {
        let wire = run(1, 0, false);
        run(3, 1, true);
        let layout = frames(&wire);
        let (_, check, size) = *layout.iter().find(|x| x.0 == 8).unwrap();
        assert_eq!(size, 96);
        let (_, cope, _) = *layout.iter().find(|x| x.0 == 6).unwrap();
        for fault in 0..3 {
            let mut bad = wire.clone();
            match fault {
                0 => {
                    bad[check + 48] ^= 1;
                    decode_k6(&bad[check + 48..check + 96]).unwrap();
                }
                1 => bad[cope..cope + 8].copy_from_slice(&volta_field::P.to_le_bytes()),
                _ => {
                    bad.pop();
                }
            }
            let mut replay =
                Tape { inner: io::Cursor::new(bad), read: Vec::new(), written: Vec::new() };
            let result = verifier_with_rng(
                &mut replay,
                context(1, 0),
                0,
                &mut StdRng::seed_from_u64(0x6100),
            );
            assert!(result.is_err());
            let tags: Vec<_> = frames(&replay.written).iter().map(|x| x.0).collect();
            assert!(!tags.contains(&9)); // no alpha after any failed check
            assert_eq!(tags.contains(&7), fault != 1); // all corrections before challenge
        }
    }

    #[test]
    fn aes_cope_independent_openssl_vectors_and_bounds() {
        // Reproduce via scripts/c71_seed6_aes_kat.py (OpenSSL + hashlib).
        for (rows, row, expected) in [
            (7, 0, 17378086631467870106),
            (7, 6, 12601397439650066912),
            (9, 0, 12432891891460850515),
            (9, 8, 14342868536689310266),
        ] {
            let profile = AesPrfProfile { rows, ot_count: OTS, domain: AES_DOMAIN };
            let mut work = crate::c71_bootstrap::Work::default();
            assert_eq!(
                aes_prf_for_profile(&[0x42; 32], b"C71S6-kat", 17, 1, row, profile, &mut work)
                    .unwrap(),
                expected
            );
            assert_eq!(work.field_candidates, 8);
            assert_eq!(work.aes_key_schedules, rows.next_power_of_two().ilog2() as u64);
            for (i, j, r) in [(OTS, 1, row), (17, 2, row), (17, 1, rows)] {
                assert!(aes_prf_for_profile(
                    &[0x42; 32],
                    b"C71S6-kat",
                    i,
                    j,
                    r,
                    profile,
                    &mut work
                )
                .is_err());
            }
        }
        assert!(checked_rows(0).is_err());
        assert!(checked_rows(usize::MAX).is_err());
        assert!(prover_with_rng(
            io::Cursor::new(Vec::new()),
            context(1, 0),
            2,
            &mut StdRng::seed_from_u64(0)
        )
        .is_err());
    }

    #[test]
    fn frame_header_rejects_wrong_length_before_payload_allocation() {
        let mut wire = Vec::new();
        wire.push(7);
        wire.extend(49u64.to_le_bytes());
        assert!(recv_header(&mut io::Cursor::new(wire), 7, 48).is_err());
    }
}

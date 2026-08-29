use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Instant;
use volta_accel::{
    Backend, C41PackedProverDeviceLot, C41PackedVerifierDeviceLot, DeviceBuffer, DeviceElement,
    Fp2Repr, Operation,
};
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverSubAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcg::{
    expand_phase_b_production, PhaseAParams, ResponseAuthorizationStore, SessionBinding,
};
use volta_proto::c41_folded_tole::{
    c41_expand_packed_cells_reference, c41_expand_packed_keys_reference, c41_typed_setup_exchange,
    C41TypedSetupExchange, C41_BITS_PER_PACKED_CELL, C41_PRG_USABLE_BITS, C41_SEED_BITS,
};

const PRODUCTION_CELLS: usize = 3_110_400;
const PRODUCTION_SEED_ROWS: usize = 253;
const C4_SETUP_BYTES: u64 = 38_371_465;
const LOT_MAGIC: &[u8; 8] = b"C41LOT1\0";
const LOT_HEADER_BYTES: usize = 80;
const LOT_DIGEST_BYTES: usize = 32;
const LOT_VERSION: u16 = 1;
const LOT_PROVER: u8 = 1;
const LOT_VERIFIER: u8 = 2;
const LOT_IO_BYTES: usize = 16 * 1024 * 1024;

struct SetupRun {
    exchange: C41TypedSetupExchange,
    public_seed: [u8; 32],
    delta: Fp2,
    typed_setup_wall_ns: u64,
    real_pcg: Option<Value>,
}

trait LotElement: DeviceElement {
    fn canonical(values: &[Self]) -> bool;
}

impl LotElement for u8 {
    fn canonical(_: &[Self]) -> bool {
        true
    }
}

impl LotElement for u16 {
    fn canonical(_: &[Self]) -> bool {
        true
    }
}

impl LotElement for Fp2Repr {
    fn canonical(values: &[Self]) -> bool {
        values.iter().all(|value| value.c0 < volta_field::P && value.c1 < volta_field::P)
    }
}

fn bytes<T: LotElement>(values: &[T]) -> &[u8] {
    // SAFETY: LotElement is local and implemented only for padding-free POD
    // types with a frozen little-endian file representation on this x86 pod.
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast(), std::mem::size_of_val(values)) }
}

fn bytes_mut<T: LotElement>(values: &mut [T]) -> &mut [u8] {
    // SAFETY: as above; the slice owns the exact initialized destination.
    unsafe {
        std::slice::from_raw_parts_mut(values.as_mut_ptr().cast(), std::mem::size_of_val(values))
    }
}

fn lot_payload_bytes(party: u8, cells: usize) -> Result<u64, Box<dyn Error>> {
    let cells = u64::try_from(cells)?;
    let bytes = match party {
        LOT_PROVER => 2 * 12 * cells * 16 + cells * 2 + cells,
        LOT_VERIFIER => 2 * cells * 16,
        _ => return Err("invalid C4.1 lot party".into()),
    };
    Ok(bytes)
}

fn lot_header(
    party: u8,
    cells: usize,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<[u8; LOT_HEADER_BYTES], Box<dyn Error>> {
    let mut header = [0u8; LOT_HEADER_BYTES];
    header[..8].copy_from_slice(LOT_MAGIC);
    header[8..10].copy_from_slice(&LOT_VERSION.to_le_bytes());
    header[10] = party;
    header[12..16].copy_from_slice(&volta_accel::CUDA_ABI_VERSION.to_le_bytes());
    header[16..24].copy_from_slice(&u64::try_from(cells)?.to_le_bytes());
    header[24..32].copy_from_slice(&u64::try_from(first_global_bit)?.to_le_bytes());
    header[32..64].copy_from_slice(&public_seed);
    header[64..72].copy_from_slice(&lot_payload_bytes(party, cells)?.to_le_bytes());
    Ok(header)
}

fn validate_lot_header(
    header: &[u8; LOT_HEADER_BYTES],
    party: u8,
    cells: usize,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    if &header[..8] != LOT_MAGIC
        || u16::from_le_bytes(header[8..10].try_into()?) != LOT_VERSION
        || header[10] != party
        || header[11] != 0
        || u32::from_le_bytes(header[12..16].try_into()?) != volta_accel::CUDA_ABI_VERSION
        || u64::from_le_bytes(header[16..24].try_into()?) != u64::try_from(cells)?
        || u64::from_le_bytes(header[24..32].try_into()?) != u64::try_from(first_global_bit)?
        || header[32..64] != public_seed
        || u64::from_le_bytes(header[64..72].try_into()?) != lot_payload_bytes(party, cells)?
        || header[72..].iter().any(|byte| *byte != 0)
    {
        return Err("noncanonical C4.1 persisted-lot header".into());
    }
    Ok(())
}

fn create_lot_file(path: &Path) -> Result<File, Box<dyn Error>> {
    if path.starts_with(std::env::current_dir()?) {
        return Err("C4.1 secret lots must be stored outside the repository".into());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?)
}

fn write_device<T: LotElement>(
    backend: &mut Backend,
    file: &mut File,
    digest: &mut blake3::Hasher,
    buffer: &DeviceBuffer<T>,
) -> Result<(), Box<dyn Error>> {
    let chunk = (LOT_IO_BYTES / size_of::<T>()).max(1);
    for start in (0..buffer.len()).step_by(chunk) {
        let values = backend.download_device(buffer, start, chunk.min(buffer.len() - start))?;
        if !T::canonical(&values) {
            return Err("noncanonical C4.1 persisted-lot element".into());
        }
        let encoded = bytes(&values);
        digest.update(encoded);
        file.write_all(encoded)?;
    }
    Ok(())
}

fn finish_lot_file(file: &mut File, digest: blake3::Hasher) -> Result<String, Box<dyn Error>> {
    let digest = digest.finalize();
    file.write_all(digest.as_bytes())?;
    file.sync_all()?;
    let status = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status).into());
    }
    Ok(digest.to_hex().to_string())
}

fn write_prover_lot(
    backend: &mut Backend,
    path: &Path,
    lot: &C41PackedProverDeviceLot,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let header = lot_header(LOT_PROVER, lot.cells, first_global_bit, public_seed)?;
    let mut file = create_lot_file(path)?;
    let mut digest = blake3::Hasher::new_derive_key("volta-zk/c41/persisted-lot/v1");
    digest.update(&header);
    file.write_all(&header)?;
    write_device(backend, &mut file, &mut digest, &lot.a)?;
    write_device(backend, &mut file, &mut digest, &lot.b)?;
    write_device(backend, &mut file, &mut digest, &lot.a_values)?;
    write_device(backend, &mut file, &mut digest, &lot.b_values)?;
    finish_lot_file(&mut file, digest)
}

fn write_verifier_lot(
    backend: &mut Backend,
    path: &Path,
    lot: &C41PackedVerifierDeviceLot,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let header = lot_header(LOT_VERIFIER, lot.cells, first_global_bit, public_seed)?;
    let mut file = create_lot_file(path)?;
    let mut digest = blake3::Hasher::new_derive_key("volta-zk/c41/persisted-lot/v1");
    digest.update(&header);
    file.write_all(&header)?;
    write_device(backend, &mut file, &mut digest, &lot.a_keys)?;
    write_device(backend, &mut file, &mut digest, &lot.b_keys)?;
    finish_lot_file(&mut file, digest)
}

fn open_lot_file(
    path: &Path,
    party: u8,
    cells: usize,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<(File, blake3::Hasher), Box<dyn Error>> {
    let mut file = File::open(path)?;
    let expected =
        LOT_HEADER_BYTES as u64 + lot_payload_bytes(party, cells)? + LOT_DIGEST_BYTES as u64;
    if file.metadata()?.len() != expected {
        return Err("truncated or trailing C4.1 persisted-lot bytes".into());
    }
    let mut header = [0u8; LOT_HEADER_BYTES];
    file.read_exact(&mut header)?;
    validate_lot_header(&header, party, cells, first_global_bit, public_seed)?;
    let mut digest = blake3::Hasher::new_derive_key("volta-zk/c41/persisted-lot/v1");
    digest.update(&header);
    Ok((file, digest))
}

fn read_device<T: LotElement>(
    backend: &mut Backend,
    file: &mut File,
    digest: &mut blake3::Hasher,
    count: usize,
) -> Result<DeviceBuffer<T>, Box<dyn Error>> {
    let output = backend.alloc_device(count)?;
    let chunk = (LOT_IO_BYTES / size_of::<T>()).max(1).min(count);
    let pinned = backend.alloc_pinned_host::<T>(chunk)?;
    let mut values = vec![T::default(); chunk];
    for start in (0..count).step_by(chunk) {
        let take = chunk.min(count - start);
        file.read_exact(bytes_mut(&mut values[..take]))?;
        if !T::canonical(&values[..take]) {
            return Err("noncanonical C4.1 reloaded-lot element".into());
        }
        digest.update(bytes(&values[..take]));
        backend.write_pinned_host(&pinned, 0, &values[..take])?;
        backend.upload_pinned_device(&pinned, 0, &output, start, take)?;
        backend.wait_pinned_host_ready(&pinned)?;
    }
    backend.free_pinned_host(pinned)?;
    Ok(output)
}

fn finish_lot_read(file: &mut File, digest: blake3::Hasher) -> Result<(), Box<dyn Error>> {
    let mut encoded = [0u8; LOT_DIGEST_BYTES];
    file.read_exact(&mut encoded)?;
    if encoded != *digest.finalize().as_bytes() {
        return Err("C4.1 persisted-lot digest mismatch".into());
    }
    Ok(())
}

fn read_prover_lot(
    backend: &mut Backend,
    path: &Path,
    cells: usize,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<C41PackedProverDeviceLot, Box<dyn Error>> {
    let (mut file, mut digest) =
        open_lot_file(path, LOT_PROVER, cells, first_global_bit, public_seed)?;
    let a = read_device(backend, &mut file, &mut digest, 12 * cells)?;
    let b = read_device(backend, &mut file, &mut digest, 12 * cells)?;
    let a_values = read_device(backend, &mut file, &mut digest, cells)?;
    let b_values = read_device(backend, &mut file, &mut digest, cells)?;
    finish_lot_read(&mut file, digest)?;
    Ok(C41PackedProverDeviceLot { a, b, a_values, b_values, cells })
}

fn read_verifier_lot(
    backend: &mut Backend,
    path: &Path,
    cells: usize,
    first_global_bit: usize,
    public_seed: [u8; 32],
) -> Result<C41PackedVerifierDeviceLot, Box<dyn Error>> {
    let (mut file, mut digest) =
        open_lot_file(path, LOT_VERIFIER, cells, first_global_bit, public_seed)?;
    let a_keys = read_device(backend, &mut file, &mut digest, cells)?;
    let b_keys = read_device(backend, &mut file, &mut digest, cells)?;
    finish_lot_read(&mut file, digest)?;
    Ok(C41PackedVerifierDeviceLot { a_keys, b_keys, cells })
}

fn random_identity() -> Result<[u8; 32], Box<dyn Error>> {
    let mut value = [0u8; 32];
    OsRng.try_fill_bytes(&mut value)?;
    if value == [0; 32] {
        return Err("OS entropy returned a zero C4.1 identity".into());
    }
    Ok(value)
}

fn setup_mock(rows: usize) -> Result<SetupRun, Box<dyn Error>> {
    let delta = Fp2::new(Fp::new(0xC41), Fp::new(0xA100));
    let public_seed = [0x74; 32];
    let mut prover = CorrelationStream::new([0x71; 32]);
    let mut verifier = VerifierCtx::new([0x71; 32], delta);
    let mut prover_tx = Transcript::new([0x72; 32]);
    let mut verifier_tx = Transcript::new([0x72; 32]);
    let started = Instant::now();
    let exchange = c41_typed_setup_exchange(
        [0x73; 32],
        public_seed,
        rows,
        0x4_1000,
        0x5_1000,
        &mut prover,
        &mut verifier,
        &mut prover_tx,
        &mut verifier_tx,
    )?;
    Ok(SetupRun {
        exchange,
        public_seed,
        delta,
        typed_setup_wall_ns: started.elapsed().as_nanos() as u64,
        real_pcg: None,
    })
}

fn setup_real(rows: usize, store_path: &Path) -> Result<SetupRun, Box<dyn Error>> {
    let sub_corrs = rows.checked_mul(C41_SEED_BITS).ok_or("C4.1 real-PCG count overflow")?;
    let store = ResponseAuthorizationStore::new(store_path)?;
    let binding = SessionBinding::new(random_identity()?, random_identity()?, random_identity()?)?;
    let started = Instant::now();
    let production = expand_phase_b_production(
        &store,
        binding,
        sub_corrs,
        1,
        PhaseAParams::for_counts(sub_corrs, 1),
    )?;
    let setup_wall_ns = started.elapsed().as_nanos() as u64;
    let comm = &production.expansion.setup.comm;
    let timings = production.expansion.timings;
    let audit = &production.production;
    let real_pcg = json!({
        "backend": "real/AES-128-MMO",
        "setup_wall_ns": setup_wall_ns,
        "setup_comm_total_bytes": comm.total_bytes,
        "setup_comm_prover_to_verifier_bytes": comm.prover_to_verifier_bytes,
        "setup_comm_verifier_to_prover_bytes": comm.verifier_to_prover_bytes,
        "setup_comm_base_ot_bytes": comm.base_ot_bytes,
        "setup_comm_ot_extension_bytes": comm.ot_extension_bytes,
        "setup_comm_ggm_bytes": comm.ggm_bytes,
        "setup_comm_consistency_bytes": comm.consistency_bytes,
        "base_ot_wall_s": timings.t_base_ot_s,
        "ot_extension_wall_s": timings.t_ot_extension_s,
        "base_vole_wall_s": timings.t_base_vole_from_setup_s,
        "ggm_pprf_wall_s": timings.t_ggm_pprf_s,
        "lpn_expand_wall_s": timings.t_lpn_expand_s,
        "full_combine_wall_s": timings.t_full_combine_s,
        "consistency_check_wall_s": timings.t_consistency_check_s,
        "total_setup_and_expansion_wall_s": timings.t_total_setup_and_expansion_s,
        "independent_role_entropy_samples": audit.independent_role_entropy_samples,
        "role_seed_commitments_distinct": audit.role_seed_commitments_distinct,
        "session_channel_identity_bound": audit.session_channel_identity_bound,
        "authorization_burned_before_setup": audit.response_authorization_burned_before_setup,
        "reconnect_retry_resume_allowed": audit.reconnect_retry_resume_allowed,
    });
    let delta = production.expansion.verifier_delta;
    let public_seed = random_identity()?;
    let secret_entropy = random_identity()?;
    let mut prover = CorrelationStream::from_pcg_pool(production.expansion.prover);
    let mut verifier = VerifierCtx::from_pcg_pool(delta, production.expansion.verifier);
    let transcript_seed = random_identity()?;
    let mut prover_tx = Transcript::new(transcript_seed);
    let mut verifier_tx = Transcript::new(transcript_seed);
    let started = Instant::now();
    let exchange = c41_typed_setup_exchange(
        secret_entropy,
        public_seed,
        rows,
        0x4_1000,
        0x5_1000,
        &mut prover,
        &mut verifier,
        &mut prover_tx,
        &mut verifier_tx,
    )?;
    Ok(SetupRun {
        exchange,
        public_seed,
        delta,
        typed_setup_wall_ns: started.elapsed().as_nanos() as u64,
        real_pcg: Some(real_pcg),
    })
}

fn prover_rows(exchange: &C41TypedSetupExchange) -> Vec<Vec<ProverSubAuthed>> {
    exchange
        .prover
        .bits
        .chunks_exact(C41_SEED_BITS)
        .zip(exchange.prover.tags.chunks_exact(C41_SEED_BITS))
        .map(|(bits, tags)| {
            bits.iter()
                .zip(tags)
                .map(|(&bit, &tag)| ProverSubAuthed::new(Fp::new(u64::from(bit)), tag))
                .collect()
        })
        .collect()
}

fn verifier_rows(exchange: &C41TypedSetupExchange) -> Vec<Vec<VerifierKey>> {
    exchange
        .verifier
        .keys
        .chunks_exact(C41_SEED_BITS)
        .map(|row| row.iter().copied().map(VerifierKey::new).collect())
        .collect()
}

fn upload_setup(
    backend: &mut Backend,
    exchange: &C41TypedSetupExchange,
) -> Result<
    (
        volta_accel::DeviceBuffer<u8>,
        volta_accel::DeviceBuffer<Fp2Repr>,
        volta_accel::DeviceBuffer<Fp2Repr>,
    ),
    Box<dyn Error>,
> {
    Ok((
        backend.upload_new_device(&exchange.prover.bits)?,
        backend.upload_new_device(
            &exchange.prover.tags.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
        )?,
        backend.upload_new_device(
            &exchange.verifier.keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
        )?,
    ))
}

fn free_prover_lot(
    backend: &mut Backend,
    lot: C41PackedProverDeviceLot,
) -> Result<(), Box<dyn Error>> {
    backend.free_device(lot.a)?;
    backend.free_device(lot.b)?;
    backend.free_device(lot.a_values)?;
    backend.free_device(lot.b_values)?;
    Ok(())
}

fn free_verifier_lot(
    backend: &mut Backend,
    lot: C41PackedVerifierDeviceLot,
) -> Result<(), Box<dyn Error>> {
    backend.free_device(lot.a_keys)?;
    backend.free_device(lot.b_keys)?;
    Ok(())
}

fn small_differential(backend: &mut Backend) -> Result<(), Box<dyn Error>> {
    let run = setup_mock(2)?;
    let exchange = &run.exchange;
    let first = C41_PRG_USABLE_BITS - 9;
    let cells = 2;
    let expected_p =
        c41_expand_packed_cells_reference(run.public_seed, &prover_rows(exchange), first, cells)?;
    let expected_v = c41_expand_packed_keys_reference(
        run.public_seed,
        run.delta,
        &verifier_rows(exchange),
        first,
        cells,
    )?;
    let (bits, tags, keys) = upload_setup(backend, exchange)?;
    let prover =
        backend.c41_expand_packed_prover_device(&bits, &tags, run.public_seed, first, cells)?;
    let verifier = backend.c41_expand_packed_verifier_device(
        &keys,
        run.public_seed,
        run.delta,
        first,
        cells,
    )?;
    let got_a = backend.download_device(&prover.a, 0, prover.a.len())?;
    let got_b = backend.download_device(&prover.b, 0, prover.b.len())?;
    let got_av = backend.download_device(&prover.a_values, 0, cells)?;
    let got_bv = backend.download_device(&prover.b_values, 0, cells)?;
    let got_ak = backend.download_device(&verifier.a_keys, 0, cells)?;
    let got_bk = backend.download_device(&verifier.b_keys, 0, cells)?;
    let expected_bv = (0..cells)
        .map(|cell| (expected_p.b_bitmap[cell / 8] >> (cell % 8)) & 1)
        .collect::<Vec<_>>();
    if got_a != expected_p.a.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_b != expected_p.b.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_av != expected_p.a_values
        || got_bv != expected_bv
        || got_ak != expected_v.a_keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_bk != expected_v.b_keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
    {
        return Err("C4.1 setup CUDA/reference differential mismatch".into());
    }
    free_prover_lot(backend, prover)?;
    free_verifier_lot(backend, verifier)?;
    backend.free_device(bits)?;
    backend.free_device(tags)?;
    backend.free_device(keys)?;
    Ok(())
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn device_edges<T: DeviceElement + PartialEq>(
    backend: &mut Backend,
    buffer: &DeviceBuffer<T>,
) -> Result<[T; 2], Box<dyn Error>> {
    let first = backend.download_device(buffer, 0, 1)?[0];
    let last = backend.download_device(buffer, buffer.len() - 1, 1)?[0];
    Ok([first, last])
}

fn clean_git_sha() -> Result<String, Box<dyn Error>> {
    let status = std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("C4.1 lot record requires a clean source tree".into());
    }
    let output = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    if !output.status.success() {
        return Err("cannot resolve C4.1 lot source SHA".into());
    }
    let sha = String::from_utf8(output.stdout)?.trim().to_owned();
    if sha.len() != 40 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("C4.1 lot source SHA is not canonical".into());
    }
    Ok(sha)
}

fn main() -> Result<(), Box<dyn Error>> {
    if !cfg!(target_endian = "little") {
        return Err("C4.1 persisted lots require a little-endian host".into());
    }
    let git_sha = clean_git_sha()?;
    let mut args = std::env::args().skip(1);
    let cells = args.next().map(|value| value.parse()).transpose()?.unwrap_or(PRODUCTION_CELLS);
    let samples: usize = args.next().map(|value| value.parse()).transpose()?.unwrap_or(3);
    let lot: usize = args.next().map(|value| value.parse()).transpose()?.unwrap_or(0);
    if cells == 0 || samples == 0 || lot >= 5 || args.next().is_some() {
        return Err("usage: c41_setup_lot_spike [cells] [samples] [lot:0..4]".into());
    }
    let first_global_bit = lot
        .checked_mul(cells)
        .and_then(|value| value.checked_mul(C41_BITS_PER_PACKED_CELL))
        .ok_or("C4.1 lot offset overflow")?;
    if first_global_bit + cells * C41_BITS_PER_PACKED_CELL
        > PRODUCTION_SEED_ROWS * C41_PRG_USABLE_BITS
    {
        return Err("C4.1 requested lot exceeds the five-response seed inventory".into());
    }

    let mut backend = Backend::cuda_resident()?;
    small_differential(&mut backend)?;
    let setup_run = match std::env::var_os("VOLTA_C41_REAL_PCG_STORE") {
        Some(path) => setup_real(PRODUCTION_SEED_ROWS, Path::new(&path))?,
        None => setup_mock(PRODUCTION_SEED_ROWS)?,
    };
    let exchange = &setup_run.exchange;
    let seed_auth_wall_ns = setup_run.typed_setup_wall_ns;
    let (bits, tags, keys) = upload_setup(&mut backend, &exchange)?;

    let mut prover_kernel_ns = Vec::with_capacity(samples);
    let mut prover_wall_ns = Vec::with_capacity(samples);
    let mut verifier_kernel_ns = Vec::with_capacity(samples);
    let mut verifier_wall_ns = Vec::with_capacity(samples);
    let mut final_prover = None;
    let mut final_verifier = None;
    for sample in 0..samples {
        backend.begin_measurement()?;
        let prover = backend.c41_expand_packed_prover_device(
            &bits,
            &tags,
            setup_run.public_seed,
            first_global_bit,
            cells,
        )?;
        let _ = backend.download_device(&prover.a_values, 0, 1)?;
        let stats = backend.finish_measurement()?;
        let auth = stats.operation(Operation::AuthMasks);
        if auth.calls != 1 {
            return Err("C4.1 prover lot expansion did not record one CUDA call".into());
        }
        prover_kernel_ns.push(auth.kernel_ns);
        prover_wall_ns.push(stats.measurement_wall_ns);

        backend.begin_measurement()?;
        let verifier = backend.c41_expand_packed_verifier_device(
            &keys,
            setup_run.public_seed,
            setup_run.delta,
            first_global_bit,
            cells,
        )?;
        let _ = backend.download_device(&verifier.a_keys, 0, 1)?;
        let stats = backend.finish_measurement()?;
        let auth = stats.operation(Operation::AuthMasks);
        if auth.calls != 1 {
            return Err("C4.1 verifier lot expansion did not record one CUDA call".into());
        }
        verifier_kernel_ns.push(auth.kernel_ns);
        verifier_wall_ns.push(stats.measurement_wall_ns);

        if sample + 1 == samples {
            final_prover = Some(prover);
            final_verifier = Some(verifier);
        } else {
            free_prover_lot(&mut backend, prover)?;
            free_verifier_lot(&mut backend, verifier)?;
        }
    }
    let prover_kernel_median_ns = median(&mut prover_kernel_ns);
    let prover_wall_median_ns = median(&mut prover_wall_ns);
    let verifier_kernel_median_ns = median(&mut verifier_kernel_ns);
    let verifier_wall_median_ns = median(&mut verifier_wall_ns);
    let mut final_prover = final_prover.expect("one sample");
    let mut final_verifier = final_verifier.expect("one sample");
    let persistence = match (
        std::env::var_os("VOLTA_C41_PROVER_LOT_FILE"),
        std::env::var_os("VOLTA_C41_VERIFIER_LOT_FILE"),
    ) {
        (None, None) => None,
        (Some(prover_path), Some(verifier_path)) => {
            let prover_path = Path::new(&prover_path);
            let verifier_path = Path::new(&verifier_path);
            if prover_path == verifier_path {
                return Err("C4.1 prover and verifier lots require separate files".into());
            }
            let prover_edges = (
                device_edges(&mut backend, &final_prover.a)?,
                device_edges(&mut backend, &final_prover.b)?,
                device_edges(&mut backend, &final_prover.a_values)?,
                device_edges(&mut backend, &final_prover.b_values)?,
            );
            let verifier_edges = (
                device_edges(&mut backend, &final_verifier.a_keys)?,
                device_edges(&mut backend, &final_verifier.b_keys)?,
            );
            let started = Instant::now();
            let prover_digest = write_prover_lot(
                &mut backend,
                prover_path,
                &final_prover,
                first_global_bit,
                setup_run.public_seed,
            )?;
            let prover_write_wall_ns = started.elapsed().as_nanos() as u64;
            let started = Instant::now();
            let verifier_digest = write_verifier_lot(
                &mut backend,
                verifier_path,
                &final_verifier,
                first_global_bit,
                setup_run.public_seed,
            )?;
            let verifier_write_wall_ns = started.elapsed().as_nanos() as u64;
            free_prover_lot(&mut backend, final_prover)?;
            free_verifier_lot(&mut backend, final_verifier)?;
            backend.trim_device_cache()?;

            backend.begin_measurement()?;
            final_prover = read_prover_lot(
                &mut backend,
                prover_path,
                cells,
                first_global_bit,
                setup_run.public_seed,
            )?;
            let prover_reload = backend.finish_measurement()?;
            backend.begin_measurement()?;
            final_verifier = read_verifier_lot(
                &mut backend,
                verifier_path,
                cells,
                first_global_bit,
                setup_run.public_seed,
            )?;
            let verifier_reload = backend.finish_measurement()?;
            let reload_edges_match = prover_edges
                == (
                    device_edges(&mut backend, &final_prover.a)?,
                    device_edges(&mut backend, &final_prover.b)?,
                    device_edges(&mut backend, &final_prover.a_values)?,
                    device_edges(&mut backend, &final_prover.b_values)?,
                )
                && verifier_edges
                    == (
                        device_edges(&mut backend, &final_verifier.a_keys)?,
                        device_edges(&mut backend, &final_verifier.b_keys)?,
                    );
            if !reload_edges_match {
                return Err("C4.1 persisted-lot H2D edge differential failed".into());
            }
            let prover_file_bytes = std::fs::metadata(prover_path)?.len();
            let verifier_file_bytes = std::fs::metadata(verifier_path)?.len();
            Some(json!({
                "party_separated_files": true,
                "codec": "C41LOT1; strict header; canonical limbs; BLAKE3 trailer",
                "reload_path": "cold file -> 16 MiB pinned chunks -> cudaMemcpyAsync DMA",
                "page_cache_discard_requested": true,
                "reload_edges_match": true,
                "prover_file_bytes": prover_file_bytes,
                "prover_file_digest": prover_digest,
                "prover_write_wall_ns": prover_write_wall_ns,
                "prover_reload_wall_ns": prover_reload.measurement_wall_ns,
                "prover_reload_h2d_bytes": prover_reload.h2d_bytes,
                "prover_reload_h2d_host_calls": prover_reload.resident_h2d_host_calls,
                "prover_reload_sync_upload_lifetime": prover_reload.sync_upload_lifetime,
                "prover_reload_bytes_per_second":
                    prover_file_bytes as f64 * 1e9 / prover_reload.measurement_wall_ns as f64,
                "verifier_file_bytes": verifier_file_bytes,
                "verifier_file_digest": verifier_digest,
                "verifier_write_wall_ns": verifier_write_wall_ns,
                "verifier_reload_wall_ns": verifier_reload.measurement_wall_ns,
                "verifier_reload_h2d_bytes": verifier_reload.h2d_bytes,
                "verifier_reload_h2d_host_calls": verifier_reload.resident_h2d_host_calls,
                "verifier_reload_sync_upload_lifetime": verifier_reload.sync_upload_lifetime,
                "verifier_reload_bytes_per_second":
                    verifier_file_bytes as f64 * 1e9 / verifier_reload.measurement_wall_ns as f64,
            }))
        }
        _ => return Err("both C4.1 party-separated lot paths are required".into()),
    };
    let memory = backend.stats()?;
    let proof = exchange.proof.encode()?;
    let combined_c4_and_typed_setup_bytes = setup_run.real_pcg.as_ref().map(|pcg| {
        C4_SETUP_BYTES
            + pcg["setup_comm_total_bytes"].as_u64().expect("real-PCG byte count")
            + exchange.metrics.total_typed_setup_bytes
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "c41-setup-lot-spike-v1",
            "credit": false,
            "git_sha": git_sha,
            "git_dirty": false,
            "cuda_abi": volta_accel::CUDA_ABI_VERSION,
            "cells": cells,
            "samples": samples,
            "lot": lot,
            "seed_rows": PRODUCTION_SEED_ROWS,
            "authenticated_seed_bits": exchange.prover.bits.len(),
            "typed_setup_proof_bytes": proof.len(),
            "typed_setup_prover_to_verifier_bytes": exchange.metrics.prover_to_verifier_bytes,
            "typed_setup_verifier_to_prover_bytes": exchange.metrics.verifier_to_prover_bytes,
            "typed_setup_total_bytes": exchange.metrics.total_typed_setup_bytes,
            "seed_auth_and_bitness_wall_ns": seed_auth_wall_ns,
            "prover_lot_kernel_median_ns": prover_kernel_median_ns,
            "prover_lot_wall_median_ns": prover_wall_median_ns,
            "prover_lots_per_second": 1e9f64 / prover_wall_median_ns as f64,
            "verifier_lot_kernel_median_ns": verifier_kernel_median_ns,
            "verifier_lot_wall_median_ns": verifier_wall_median_ns,
            "verifier_lots_per_second": 1e9f64 / verifier_wall_median_ns as f64,
            "prover_slab_bytes": 2 * 12 * cells * size_of::<Fp2Repr>(),
            "prover_plaintext_mask_bytes": cells * (size_of::<u16>() + size_of::<u8>()),
            "verifier_key_bytes": 2 * cells * size_of::<Fp2Repr>(),
            "peak_device_bytes": memory.peak_device_bytes,
            "conditional_soundness_bits": exchange.metrics.conditional_soundness_bits,
            "conditional_weight_zk_bits": exchange.metrics.conditional_weight_zk_bits,
            "small_nonzero_cpu_cuda_differential": true,
            "real_pcg": setup_run.real_pcg,
            "combined_c4_and_typed_setup_bytes": combined_c4_and_typed_setup_bytes,
            "persistence": persistence
        }))?
    );

    free_prover_lot(&mut backend, final_prover)?;
    free_verifier_lot(&mut backend, final_verifier)?;
    backend.free_device(bits)?;
    backend.free_device(tags)?;
    backend.free_device(keys)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_lot_header_is_strict_and_party_separated() {
        let seed = [0x41; 32];
        let prover = lot_header(LOT_PROVER, 8, 17, seed).unwrap();
        validate_lot_header(&prover, LOT_PROVER, 8, 17, seed).unwrap();
        assert!(validate_lot_header(&prover, LOT_VERIFIER, 8, 17, seed).is_err());
        let mut tampered = prover;
        tampered[79] = 1;
        assert!(validate_lot_header(&tampered, LOT_PROVER, 8, 17, seed).is_err());
    }
}

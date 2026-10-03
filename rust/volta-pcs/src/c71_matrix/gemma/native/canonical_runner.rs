//! Explicit, non-admitted CPU reference. No GPU fallback or provider actions.
//! Full canonical execution is heavy and MUST NOT run on the development VM.
//! This executable does not certify calibration, provenance, HBM, or readiness.
use super::*;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use volta_pcg::{
    c71_lifetime::Lifetime,
    c71_seed6::{self, Geometry},
};

struct Counted<T> {
    channel: T,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}
impl<T: Read> Read for Counted<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.channel.read(bytes)?;
        self.received.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}
impl<T: Write> Write for Counted<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.channel.write(bytes)?;
        self.sent.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

impl Response {
    fn write(&self, channel: &mut impl Write) -> io::Result<()> {
        if self.root.num_roots() != 1 || self.certificate.len() > kernel::wire::CANONICAL_MAX_BYTES
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response shape"));
        }
        channel.write_all(b"C71RSP01")?;
        channel.write_all(&self.root.roots()[0])?;
        for token in self.tokens {
            channel.write_all(&token.to_le_bytes())?;
        }
        channel.write_all(&self.nonce)?;
        channel.write_all(&(self.certificate.len() as u64).to_le_bytes())?;
        channel.write_all(&self.certificate)?;
        channel.flush()
    }

    fn read(channel: &mut impl Read) -> io::Result<Self> {
        let mut prefix = [0; 680];
        channel.read_exact(&mut prefix)?;
        let n = u64::from_le_bytes(prefix[672..680].try_into().unwrap());
        if &prefix[..8] != b"C71RSP01" || n > kernel::wire::CANONICAL_MAX_BYTES as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response framing"));
        }
        let tokens = std::array::from_fn(|i| {
            u32::from_le_bytes(prefix[40 + 4 * i..44 + 4 * i].try_into().unwrap())
        });
        if tokens.iter().any(|&t| t >= 262144) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response token range"));
        }
        let mut certificate = Vec::new();
        certificate.try_reserve_exact(n as usize).map_err(io::Error::other)?;
        certificate.resize(n as usize, 0);
        channel.read_exact(&mut certificate)?;
        Ok(Self {
            root: C61Commitment::new(vec![prefix[8..40].try_into().unwrap()]),
            tokens,
            nonce: prefix[640..672].try_into().unwrap(),
            certificate,
        })
    }
}

fn packed(path: &Path, cells: usize) -> Result<(Arc<Vec<i16>>, String), String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() != (2 * cells) as u64 {
        return Err("canonical packed W length differs".into());
    }
    let mut words = Vec::new();
    words.try_reserve_exact(cells).map_err(|e| e.to_string())?;
    let mut h = blake3::Hasher::new();
    let mut chunk = [0; 65536];
    while words.len() < cells {
        let count = (2 * (cells - words.len())).min(chunk.len());
        file.read_exact(&mut chunk[..count]).map_err(|e| e.to_string())?;
        h.update(&chunk[..count]);
        for bytes in chunk[..count].chunks_exact(2) {
            let word = i16::from_le_bytes(bytes.try_into().unwrap());
            if word == i16::MIN {
                return Err("canonical W contains overflow marker".into());
            }
            words.push(word);
        }
    }
    if file.read(&mut chunk[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("canonical W changed length".into());
    }
    // Arc<Vec<_>> transfers ownership without a second full-size W allocation.
    Ok((Arc::new(words), h.finalize().to_hex().to_string()))
}

pub fn command(args: &[String]) -> Result<serde_json::Value, String> {
    if args.len() != 6 || args[0] != "reference-cpu" {
        return Err("Stop: no admitted GPU runner; explicit heavy reference only: c71_canonical_reference reference-cpu CANDIDATE TABLES PACKED NEW_JOURNAL_DIRECTORY PREPARATION_BYTES".into());
    }
    let limit: usize = args[5].parse().map_err(|_| "invalid preparation budget")?;
    if limit < 98_380_800 {
        return Err("preparation budget below layer checkpoints".into());
    }
    rayon::ThreadPoolBuilder::new().num_threads(1).build_global().map_err(|e| e.to_string())?;
    let profiles: Vec<_> =
        calibration_input::profiles(Path::new(&args[1]))?.into_iter().map(Arc::new).collect();
    let input = Arc::new(calibration_input::Tables::read(Path::new(&args[2]))?);
    let cells = profiles[0].plan.sources.iter().map(|s| s.rows * s.cols).sum();
    let started = Instant::now();
    let directory = Path::new(&args[4]);
    input.with_slot(0, |t0| {
        input.with_slot(1, |t1| {
            input.with_slot(2, |t2| {
                let public = Public::from_shared(profiles, [*t0, *t1, *t2])?;
                // Reject public context/capacity before loading private W.
                let geometry = Geometry::new(675, 19, 11).map_err(|e| e.to_string())?;
                if public.required.iter().sum::<usize>() * 3
                    > geometry.capacity().map_err(|e| e.to_string())?
                {
                    return Err("canonical Seed6 capacity insufficient".into());
                }
                let (weights, packed_digest) = packed(Path::new(&args[3]), cells)?;
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(directory)
                    .map_err(|e| e.to_string())?;
                run(public, input.clone(), weights, directory, limit, started, packed_digest)
            })
        })
    })???
}

fn run(
    public: Public<'_>,
    input: Arc<calibration_input::Tables>,
    weights: Arc<Vec<i16>>,
    directory: &Path,
    limit: usize,
    started: Instant,
    packed_digest: String,
) -> Result<serde_json::Value, String> {
    let profiles = public.profiles.clone();
    let tables = public.tables;
    let geometry = Geometry::new(675, 19, 11).map_err(|e| e.to_string())?;
    if public.required.iter().sum::<usize>() * 3 > geometry.capacity().map_err(|e| e.to_string())? {
        return Err("canonical Seed6 capacity insufficient".into());
    }
    let coins = fresh_pcs_coins()?;
    let (p, original) = (profiles[0].clone(), weights.clone());
    let installed = b12::replay::ReplayModel::new(
        Domain::Flat(35),
        coins.seed,
        coins.salt_seed,
        Arc::new(move |i| {
            to_p3(
                p.plan
                    .virtual_to_packed(i)
                    .expect("compiled W layout")
                    .map_or(Fp3::ZERO, |offset| signed(i64::from(original[offset]))),
            )
        }),
        profiles[0].plan.live,
    )?;
    let root = installed.root().clone();
    let binding = public.binding(&root)?;
    let installation_seconds = started.elapsed().as_secs_f64();
    let workload: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/c7-d126-gemma31b-workload-v1.json"
    )))
    .map_err(|e| e.to_string())?;
    let prompt: Vec<u32> = serde_json::from_value(workload["prompt"]["token_ids"].clone())
        .map_err(|e| e.to_string())?;
    let prompt: [u32; 100] = prompt.try_into().map_err(|_| "pinned prompt length")?;
    let session: [u8; 32] = rand::random();
    let channel_binding: [u8; 32] = rand::random();
    let (sent, received) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    // Kernel-owned socketpairs are the authenticated local role boundary here;
    // these constructors must not be replaced by unauthenticated TCP sockets.
    let pair = || -> Result<_, String> {
        let (p, v) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
        for c in [&p, &v] {
            c.set_read_timeout(Some(std::time::Duration::from_secs(65)))
                .map_err(|e| e.to_string())?;
            c.set_write_timeout(Some(std::time::Duration::from_secs(65)))
                .map_err(|e| e.to_string())?;
        }
        Ok((p, Counted { channel: v, sent: sent.clone(), received: received.clone() }))
    };
    let (pcg_p, pcg_v) = pair()?;
    let (mut proof_p, mut proof_v) = pair()?;
    let mut pstore =
        Lifetime::install(&directory.join("prover"), binding).map_err(|e| e.to_string())?;
    let mut vstore =
        Lifetime::install(&directory.join("verifier"), binding).map_err(|e| e.to_string())?;
    let setup_started = Instant::now();
    let responses = std::thread::scope(|scope| -> Result<_, String> {
        let peer = scope.spawn(|| -> Result<_, String> {
            let mut pool = c71_seed6::prover(&mut pstore, pcg_p, session, channel_binding, geometry)
                .map_err(|e| e.to_string())?;
            let mut capacity = ProverCapacity::Seed6(&mut pool);
            let mut p = Prover::new(public, weights, installed, input, limit, &capacity)?;
            let setup_seconds = setup_started.elapsed().as_secs_f64();
            let mut responses = Vec::new();
            for slot in 0..3 {
                let began = Instant::now();
                p.respond_authenticated(&prompt, rand::random(), &mut capacity, |response| {
                    response.write(&mut proof_p).map_err(|e| e.to_string())?;
                    let mut completion = vec![0; acceptance_transport::BYTES];
                    proof_p.read_exact(&mut completion).map_err(|e| e.to_string())?;
                    Ok(completion)
                })?;
                responses.push(serde_json::json!({"slot": slot, "response_wall_seconds": began.elapsed().as_secs_f64(),
                    "accepted": true}));
            }
            capacity.stop();
            Ok((responses, setup_seconds))
        });
        let result = (|| {
            let mut pool =
                c71_seed6::verifier(&mut vstore, pcg_v, session, channel_binding, geometry)
                    .map_err(|e| e.to_string())?;
            let mut capacity = VerifierCapacity::Seed6(&mut pool);
            let mut v = Verifier::new(Public::from_shared(profiles, tables)?, root, &capacity)?;
            for _ in 0..3 {
                let response = Response::read(&mut proof_v).map_err(|e| e.to_string())?;
                v.verify_authenticated(&prompt, &response, &mut capacity, &mut proof_v)?;
            }
            capacity.stop();
            Ok::<_, String>(())
        })();
        // Disconnect on failure so a pending peer read/write cannot succeed.
        drop(proof_v);
        let output = peer.join().map_err(|_| "canonical prover panic")?;
        result?;
        output
    })?;
    if pstore.accepted_head() != vstore.accepted_head()
        || pstore.counters() != (1, 3)
        || vstore.counters() != (1, 3)
    {
        return Err("canonical role journals differ".into());
    }
    Ok(serde_json::json!({"credit": false, "readiness": false, "gpu_execution": false,
        "canonical_certificates_verified": 3, "tables_numerically_certified": false,
        "checkpoint_provenance_verified": false, "packed_blake3": packed_digest,
        "installation_wall_seconds": installation_seconds, "setup_wall_seconds": responses.1,
        "responses": responses.0, "total_wall_seconds": started.elapsed().as_secs_f64(),
        "channel_bytes_to_verifier": received.load(Ordering::Relaxed),
        "channel_bytes_from_verifier": sent.load(Ordering::Relaxed),
        "complete_communication": false,
        "communication_excludes": "out-of-band public profile, tables and installed W-root distribution",
        "complete_physical_peak": false,
        "process_status": std::fs::read_to_string("/proc/self/status").ok().map(|s| s.lines()
            .filter(|l| l.starts_with("VmHWM:") || l.starts_with("VmRSS:")).map(str::to_owned).collect::<Vec<_>>()),
        "memory_scope": "kernel process-wide host high-water mark, both roles; not phase liveness or HBM"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_canonical_runner_transport_and_default_stop() {
        assert!(command(&[]).unwrap_err().contains("no admitted GPU"));
        assert!(command(&["gpu".into()]).is_err());
        let r = Response {
            root: C61Commitment::new(vec![[1; 32]]),
            tokens: [0; 150],
            nonce: [2; 32],
            certificate: vec![3, 4, 5],
        };
        let mut bytes = Vec::new();
        r.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 683);
        let decoded = Response::read(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.root, r.root);
        assert_eq!(decoded.tokens, r.tokens);
        assert_eq!(decoded.nonce, r.nonce);
        assert_eq!(decoded.certificate, r.certificate);
        for len in [0, 679, 680, 681, 682] {
            assert!(Response::read(&mut &bytes[..len]).is_err());
        }
        bytes[672..680].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Response::read(&mut &bytes[..]).is_err());
        let (sent, received) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let mut stream = Counted {
            channel: io::Cursor::new(Vec::new()),
            sent: sent.clone(),
            received: received.clone(),
        };
        r.write(&mut stream).unwrap();
        stream.channel.set_position(0);
        Response::read(&mut stream).unwrap();
        assert_eq!(sent.load(Ordering::Relaxed), 683);
        assert_eq!(received.load(Ordering::Relaxed), 683);
    }

    #[test]
    fn c71_canonical_runner_packed_input_checks_before_installation() {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "c71-packed-reader-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&[1, 0, 255, 255]).unwrap();
        let (words, digest) = packed(&path, 2).unwrap();
        assert_eq!(words.as_slice(), &[1, -1]);
        assert_eq!(digest, blake3::hash(&[1, 0, 255, 255]).to_hex().to_string());
        assert!(packed(&path, 3).is_err());
        file.write_all(&[0, 128]).unwrap();
        assert!(packed(&path, 3).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}

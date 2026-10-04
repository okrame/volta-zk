//! Explicit, non-admitted CPU reference. No GPU fallback or provider actions.
//! Full canonical execution is heavy and MUST NOT run on the development VM.
//! This executable does not certify calibration, provenance, HBM, or readiness.
use super::metrics::{Counted, Measurements, Traffic};
use super::*;
use std::io::{Read, Write};
use std::path::Path;
use volta_pcg::{
    c71_lifetime::Lifetime,
    c71_seed6::{self, Geometry},
};

fn pair(
    traffic: Traffic,
) -> Result<(std::os::unix::net::UnixStream, Counted<std::os::unix::net::UnixStream>), String> {
    // Kernel-owned socketpairs are the authenticated local role boundary.
    // An unauthenticated TCP replacement does not preserve this premise.
    let (p, v) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    for c in [&p, &v] {
        c.set_read_timeout(Some(std::time::Duration::from_secs(65))).map_err(|e| e.to_string())?;
        c.set_write_timeout(Some(std::time::Duration::from_secs(65))).map_err(|e| e.to_string())?;
    }
    Ok((p, Counted { channel: v, traffic }))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Transport the exact public input bytes. Each role compiles its own public
// profile; numerical certification remains a separate prerequisite.
fn write_public(channel: &mut impl Write, candidate: &[u8], tables: &[u8]) -> io::Result<()> {
    if candidate.len() > 1_048_576 || tables.len() != calibration_input::Tables::BYTES {
        return Err(invalid("public input length"));
    }
    channel.write_all(b"C71PUB01")?;
    channel.write_all(&(candidate.len() as u64).to_le_bytes())?;
    channel.write_all(&(tables.len() as u64).to_le_bytes())?;
    channel.write_all(candidate)?;
    channel.write_all(tables)?;
    channel.flush()
}

fn read_public(channel: &mut impl Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut header = [0; 24];
    channel.read_exact(&mut header)?;
    let n = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let t = u64::from_le_bytes(header[16..24].try_into().unwrap());
    if &header[..8] != b"C71PUB01" || n > 1_048_576 || t != calibration_input::Tables::BYTES as u64
    {
        return Err(invalid("public input framing"));
    }
    let mut candidate = vec![0; n as usize];
    let mut tables = vec![0; t as usize];
    channel.read_exact(&mut candidate)?;
    channel.read_exact(&mut tables)?;
    Ok((candidate, tables))
}

fn with_public<T>(
    profiles: Vec<Arc<Canonical>>,
    input: &calibration_input::Tables,
    use_public: impl FnOnce(Public<'_>) -> Result<T, String>,
) -> Result<T, String> {
    input.with_slot(0, |t0| {
        input.with_slot(1, |t1| {
            input.with_slot(2, |t2| use_public(Public::from_shared(profiles, [*t0, *t1, *t2])?))
        })
    })???
}

fn write_request(channel: &mut impl Write, slot: usize, prompt: &[u32; 100]) -> io::Result<()> {
    if slot >= 3 || prompt.iter().any(|&t| t >= 262144) {
        return Err(invalid("request context"));
    }
    channel.write_all(b"C71REQ01")?;
    channel.write_all(&(slot as u64).to_le_bytes())?;
    for t in prompt {
        channel.write_all(&t.to_le_bytes())?;
    }
    channel.flush()
}

fn read_request(channel: &mut impl Read, slot: usize) -> io::Result<[u32; 100]> {
    let mut bytes = [0; 416];
    channel.read_exact(&mut bytes)?;
    if &bytes[..8] != b"C71REQ01"
        || slot >= 3
        || u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != slot as u64
    {
        return Err(invalid("request framing"));
    }
    let tokens = std::array::from_fn(|i| {
        u32::from_le_bytes(bytes[16 + 4 * i..20 + 4 * i].try_into().unwrap())
    });
    if tokens.iter().any(|&t| t >= 262144) {
        return Err(invalid("request token range"));
    }
    Ok(tokens)
}

fn write_installation(
    channel: &mut impl Write,
    binding: &ModelBinding,
    session: [u8; 32],
    channel_binding: [u8; 32],
) -> io::Result<()> {
    if binding.anchor != binding.root
        || [binding.root, binding.semantics, session, channel_binding].contains(&[0; 32])
    {
        return Err(invalid("installation context"));
    }
    channel.write_all(b"C71INS01")?;
    for value in [binding.root, binding.semantics, session, channel_binding] {
        channel.write_all(&value)?;
    }
    channel.flush()
}

fn read_installation(channel: &mut impl Read) -> io::Result<(ModelBinding, [u8; 32], [u8; 32])> {
    let mut bytes = [0; 136];
    channel.read_exact(&mut bytes)?;
    if &bytes[..8] != b"C71INS01" || bytes[8..].chunks_exact(32).any(|v| v == [0; 32]) {
        return Err(invalid("installation framing"));
    }
    let root = bytes[8..40].try_into().unwrap();
    Ok((
        ModelBinding { anchor: root, root, semantics: bytes[40..72].try_into().unwrap() },
        bytes[72..104].try_into().unwrap(),
        bytes[104..136].try_into().unwrap(),
    ))
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
    let measurements = Measurements::new();
    let phase = measurements.phase("coordinator", None, "command_total");
    let result = measured_command(args, &measurements);
    measurements.resource("before_native_cleanup", None, serde_json::Value::Null);
    let cleanup = measurements.close_native(result.is_err());
    measurements.resource(
        "native_cleanup",
        None,
        serde_json::json!({
            "success": cleanup.is_ok(), "final_stats": cleanup.as_ref().ok()
        }),
    );
    let result = result.and_then(|mut output| {
        output["native_cleanup"] =
            serde_json::to_value(cleanup?).map_err(|error| error.to_string())?;
        Ok(output)
    });
    if result.is_ok() {
        phase.finish();
    } else {
        drop(phase);
    }
    let report = measurements.report();
    match result {
        Ok(mut output) => {
            output["measurements"] = report;
            Ok(output)
        }
        Err(error) => {
            // Local diagnostics only; no witness, token, correlation or private
            // failure reason. An external timeout still needs its controller log.
            eprintln!(
                "C71_RUN_METRICS {}",
                serde_json::json!({
                    "complete": false, "credit": false, "readiness": false,
                    "measurements": report
                })
            );
            Err(error)
        }
    }
}

fn measured_command(
    args: &[String],
    measurements: &Measurements,
) -> Result<serde_json::Value, String> {
    let native = match (args.first().map(String::as_str), args.len()) {
        (Some("reference-cpu"), 6) => None,
        (Some("experiment-cuda"), 8) => Some(kernel::range::windowed::native::Config::new(
            args[6].clone().into(), args[7].parse().map_err(|_| "invalid CUDA device")?,
            6_442_450_944, 256 * 1024 * 1024, 1 << 30, 32,
        )),
        _ => return Err("Stop: explicit backend required: c71_canonical_reference reference-cpu CANDIDATE TABLES PACKED NEW_JOURNAL_DIRECTORY PREPARATION_BYTES; or experiment-cuda with LIBRARY DEVICE appended".into()),
    };
    let limit: usize = args[5].parse().map_err(|_| "invalid preparation budget")?;
    if limit < 98_380_800 {
        return Err("preparation budget below layer checkpoints".into());
    }
    if native.is_some() && !(1usize << 30..=6_174_015_488).contains(&limit) {
        return Err(
            "native preparation budget must cover the 1 GiB range window within the arena reserve"
                .into(),
        );
    }
    rayon::ThreadPoolBuilder::new().num_threads(1).build_global().map_err(|e| e.to_string())?;
    let initialization = measurements.phase("coordinator", None, "global_initialization");
    let phase = measurements.phase("prover", None, "read_and_compile_public");
    let read = |path: &str, limit: usize| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > limit {
            return Err("public input exceeds limit".into());
        }
        Ok(bytes)
    };
    let candidate = read(&args[1], 1_048_576)?;
    let table_bytes = read(&args[2], calibration_input::Tables::BYTES)?;
    let profiles: Vec<_> =
        calibration_input::profiles_from_bytes(&candidate)?.into_iter().map(Arc::new).collect();
    let input = Arc::new(calibration_input::Tables::from_bytes(&table_bytes)?);
    phase.finish();
    let phase = measurements.phase("coordinator", None, "public_distribution");
    let (mut source, mut destination) = pair(measurements.channel("public_distribution", None))?;
    let (vcandidate, vtable_bytes) = std::thread::scope(|scope| {
        let sender = scope.spawn(move || {
            write_public(&mut source, &candidate, &table_bytes).map_err(|e| e.to_string())
        });
        let received = read_public(&mut destination).map_err(|e| e.to_string());
        drop(destination); // failed decoding disconnects a blocked sender
        let sent = sender.join().map_err(|_| "public distribution panic")?;
        sent?;
        received
    })?;
    phase.finish();
    let phase = measurements.phase("verifier", None, "compile_received_public");
    let vprofiles: Vec<_> =
        calibration_input::profiles_from_bytes(&vcandidate)?.into_iter().map(Arc::new).collect();
    let vinput = calibration_input::Tables::from_bytes(&vtable_bytes)?;
    drop((vcandidate, vtable_bytes));
    measurements.resource(
        "public_table_owners",
        None,
        serde_json::json!({
            "prover_capacity_bytes": input.capacity_bytes(),
            "verifier_capacity_bytes": vinput.capacity_bytes()
        }),
    );
    phase.finish();
    let cells = profiles[0].plan.sources.iter().map(|s| s.rows * s.cols).sum();
    let directory = Path::new(&args[4]);
    with_public(profiles, &input, |public| {
        with_public(vprofiles, &vinput, |vpublic| {
            if public.digest != vpublic.digest {
                return Err("distributed public profile differs".into());
            }
            // Reject public context/capacity before loading private W.
            let geometry = Geometry::new(675, 19, 11).map_err(|e| e.to_string())?;
            if public.required.iter().sum::<usize>() * 3
                > geometry.capacity().map_err(|e| e.to_string())?
            {
                return Err("canonical Seed6 capacity insufficient".into());
            }
            let phase = measurements.phase("prover", None, "load_packed_w");
            let (weights, packed_digest) = packed(Path::new(&args[3]), cells)?;
            if native.is_some() {
                measurements.budget(&weights)?;
            }
            phase.finish();
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(directory).map_err(|e| e.to_string())?;
            initialization.finish();
            run(
                public,
                vpublic,
                input.clone(),
                weights,
                directory,
                limit,
                measurements,
                packed_digest,
                native.clone(),
            )
        })
    })
}

fn run(
    public: Public<'_>,
    vpublic: Public<'_>,
    input: Arc<calibration_input::Tables>,
    weights: Arc<Vec<i16>>,
    directory: &Path,
    limit: usize,
    measurements: &Measurements,
    packed_digest: String,
    native_config: Option<kernel::range::windowed::native::Config>,
) -> Result<serde_json::Value, String> {
    let geometry = Geometry::new(675, 19, 11).map_err(|e| e.to_string())?;
    if public.required.iter().sum::<usize>() * 3 > geometry.capacity().map_err(|e| e.to_string())? {
        return Err("canonical Seed6 capacity insufficient".into());
    }
    let native = if let Some(config) = native_config {
        let phase = measurements.phase("prover", None, "native_global_residency");
        let session = resident::Session::new(
            public.profiles.clone(),
            input.clone(),
            weights.clone(),
            config,
            limit,
        )?;
        measurements.native(session.clone());
        phase.finish();
        Some(session)
    } else {
        None
    };
    let phase = measurements.phase("prover", None, "installation_w_commitment");
    let coins = fresh_pcs_coins()?;
    let (p, original) = (public.profiles[0].clone(), weights.clone());
    let (range_profile, range_packed) = (public.profiles[0].clone(), weights.clone());
    let mut installed = b12::replay::ReplayModel::new(
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
        public.profiles[0].plan.live,
    )?
    .with_signed_range_reader(
        &weights,
        Arc::new(move |suffix, bottom, first, out| {
            range_profile.plan.range_window(35, &range_packed, first, out, suffix, bottom)
        }),
    )?;
    if let Some(session) = &native {
        installed.range_words.as_mut().ok_or("native W range source missing")?.native =
            Some(session.weight_range_config()?);
    }
    let root = installed.root().clone();
    let binding = public.binding(&root)?;
    phase.finish();
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
    let (pcg_p, pcg_v) = pair(measurements.channel("seed6_setup", None))?;
    let (mut proof_p, mut proof_v) = pair(measurements.channel("installation", None))?;
    let phase = measurements.phase("coordinator", None, "installation_distribution_and_journals");
    write_installation(&mut proof_p, &binding, session, channel_binding)
        .map_err(|e| e.to_string())?;
    let (vbinding, vsession, vchannel_binding) =
        read_installation(&mut proof_v).map_err(|e| e.to_string())?;
    if vbinding.semantics != vpublic.digest {
        return Err("installed public identity differs".into());
    }
    let vroot = C61Commitment::new(vec![vbinding.root]);
    let mut pstore =
        Lifetime::install(&directory.join("prover"), binding).map_err(|e| e.to_string())?;
    let mut vstore =
        Lifetime::install(&directory.join("verifier"), vbinding).map_err(|e| e.to_string())?;
    phase.finish();
    let session_phase = measurements.phase("coordinator", None, "session_and_responses");
    let responses = std::thread::scope(|scope| -> Result<_, String> {
        let pstore_ref = &mut pstore;
        let native = native.clone();
        let peer = scope.spawn(move || -> Result<_, String> {
            let phase = measurements.phase("prover", None, "seed6_setup");
            let mut pool = c71_seed6::prover(pstore_ref, pcg_p, session, channel_binding, geometry)
                .map_err(|e| e.to_string())?;
            phase.finish();
            let mut capacity = ProverCapacity::Seed6(&mut pool);
            let phase = measurements.phase("prover", None, "registry_initialization");
            let mut p =
                Prover::new(public, weights, installed, input, limit, &capacity, native.clone())?;
            phase.finish();
            let mut responses = Vec::new();
            for slot in 0..3 {
                let phase = measurements.phase("prover", Some(slot), "request_receive");
                let request = read_request(&mut proof_p, slot).map_err(|e| e.to_string())?;
                if request != prompt {
                    return Err("request differs from pinned workload".into());
                }
                phase.finish();
                let phase = measurements.phase("prover", Some(slot), "response_total");
                let mut body_bytes = 0;
                let (preparation_ns, inference_ns) = p.respond_authenticated(
                    &request,
                    rand::random(),
                    &mut capacity,
                    measurements,
                    |response| {
                        body_bytes = response.certificate.len();
                        response.write(&mut proof_p).map_err(|e| e.to_string())?;
                        let mut completion = vec![0; acceptance_transport::BYTES];
                        proof_p.read_exact(&mut completion).map_err(|e| e.to_string())?;
                        Ok(completion)
                    },
                )?;
                let response_ns = phase.finish();
                responses.push(serde_json::json!({"slot": slot, "response_wall_ns": response_ns,
                    "preparation_including_inference_wall_ns": preparation_ns,
                    "post_preparation_wall_ns": response_ns - preparation_ns,
                    "inference_wall_ns": inference_ns,
                    "proof_only_wall_ns": inference_ns.map(|inference| response_ns - inference),
                    "phase_partition_complete": inference_ns.is_some(),
                    "partition_scope": "inference includes mandatory KV/checkpoint/histogram capture and fences; remainder includes preparation allocation/table setup, replay, proof, exchange, verification wait and journals; no overlapped interval subtraction",
                    "certificate_body_bytes": body_bytes, "accepted": true}));
            }
            capacity.stop();
            Ok(responses)
        });
        let result = (|| {
            let phase = measurements.phase("verifier", None, "seed6_setup");
            let mut pool =
                c71_seed6::verifier(&mut vstore, pcg_v, vsession, vchannel_binding, geometry)
                    .map_err(|e| e.to_string())?;
            phase.finish();
            let mut capacity = VerifierCapacity::Seed6(&mut pool);
            let phase = measurements.phase("verifier", None, "registry_initialization");
            let mut v = Verifier::new(vpublic, vroot, &capacity)?;
            phase.finish();
            for slot in 0..3 {
                proof_v.traffic = measurements.channel("response", Some(slot));
                let phase = measurements.phase("verifier", Some(slot), "request_to_completion");
                write_request(&mut proof_v, slot, &prompt).map_err(|e| e.to_string())?;
                let read_phase =
                    measurements.phase("verifier", Some(slot), "wait_and_decode_response");
                let response = Response::read(&mut proof_v).map_err(|e| e.to_string())?;
                read_phase.finish();
                let verification =
                    measurements.phase("verifier", Some(slot), "verify_journal_and_completion");
                v.verify_authenticated(&prompt, &response, &mut capacity, &mut proof_v)?;
                verification.finish();
                phase.finish();
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
    session_phase.finish();
    if pstore.accepted_head() != vstore.accepted_head()
        || pstore.counters() != (1, 3)
        || vstore.counters() != (1, 3)
    {
        return Err("canonical role journals differ".into());
    }
    let native_stats = native.as_ref().map(|session| session.stats()).transpose()?;
    Ok(serde_json::json!({"credit": false, "readiness": false, "gpu_execution": native.is_some(),
        "backend": if native.is_some() { "cuda-producers-range-cpu-protocol" } else { "reference-cpu" },
        "native_cumulative": native_stats,
        "cpu_phases": ["public validation and table packing", "W PCS commitment and bounded 256 MiB W range gather/upload", "PCS FFT/Merkle/query/remainder and source contractions", "non-range GKR and original MAC arithmetic", "Seed6 real AES setup and expansion", "proof encoding, verifier and durable journals", "bounded original A row/byte staging for CPU protocol consumers"],
        "gpu_phases": if native.is_some() { vec!["all 13 inference and replay producers", "resident A byte gather", "range canopy/Gram/fold/reductions"] } else { vec![] },
        "canonical_certificates_verified": 3, "tables_numerically_certified": false,
        "checkpoint_provenance_verified": false, "packed_blake3": packed_digest,
        "responses": responses,
        "complete_local_application_communication": true,
        "complete_physical_peak": false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_canonical_runner_transport_and_default_stop() {
        assert!(command(&[]).unwrap_err().contains("explicit backend required"));
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
        let traffic = Traffic::default();
        let mut stream = Counted { channel: io::Cursor::new(Vec::new()), traffic: traffic.clone() };
        r.write(&mut stream).unwrap();
        stream.channel.set_position(0);
        Response::read(&mut stream).unwrap();
        assert_eq!(traffic.bytes(), (683, 683));
    }

    #[test]
    fn c71_canonical_runner_public_installation_and_request_framing() {
        let tables = vec![0; calibration_input::Tables::BYTES];
        let mut bytes = Vec::new();
        write_public(&mut bytes, b"{}", &tables).unwrap();
        assert_eq!(bytes.len(), 24 + 2 + tables.len());
        let (candidate, received) = read_public(&mut &bytes[..]).unwrap();
        assert_eq!(candidate, b"{}");
        assert_eq!(received, tables);
        assert!(calibration_input::profiles_from_bytes(&candidate).is_err());
        for len in [0, 23, 24, bytes.len() - 1] {
            assert!(read_public(&mut &bytes[..len]).is_err());
        }
        for (start, value) in [(8, u64::MAX), (16, 0), (16, u64::MAX)] {
            let mut header = bytes[..24].to_vec();
            header[start..start + 8].copy_from_slice(&value.to_le_bytes());
            // The cap must reject the header before attempting a body read/allocation.
            assert_eq!(
                read_public(&mut &header[..]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        bytes[0] ^= 1;
        assert!(read_public(&mut &bytes[..]).is_err());
        assert!(write_public(&mut Vec::new(), b"{}", &tables[..tables.len() - 1]).is_err());
        assert!(calibration_input::Tables::from_bytes(&tables[..tables.len() - 1]).is_err());

        let binding = ModelBinding { anchor: [1; 32], root: [1; 32], semantics: [2; 32] };
        let mut bytes = Vec::new();
        write_installation(&mut bytes, &binding, [3; 32], [4; 32]).unwrap();
        assert_eq!(bytes.len(), 136);
        assert!(read_installation(&mut &bytes[..]).unwrap() == (binding, [3; 32], [4; 32]));
        for len in [0, 8, 135] {
            assert!(read_installation(&mut &bytes[..len]).is_err());
        }
        bytes[8..40].fill(0);
        assert!(read_installation(&mut &bytes[..]).is_err());
        assert!(write_installation(&mut Vec::new(), &binding, [0; 32], [4; 32]).is_err());

        for slot in 0..3 {
            let mut bytes = Vec::new();
            write_request(&mut bytes, slot, &[17; 100]).unwrap();
            assert_eq!(bytes.len(), 416);
            assert_eq!(read_request(&mut &bytes[..], slot).unwrap(), [17; 100]);
            assert!(read_request(&mut &bytes[..], (slot + 1) % 3).is_err());
            assert!(read_request(&mut &bytes[..415], slot).is_err());
            bytes[16..20].copy_from_slice(&262144u32.to_le_bytes());
            assert!(read_request(&mut &bytes[..], slot).is_err());
        }
    }

    #[test]
    fn c71_canonical_runner_counted_socket_protocol_three_slots() {
        // Transport fixture only: the three bodies are not valid certificates.
        let m = Measurements::new();
        let (mut p, mut v) = pair(m.channel("public_distribution", None)).unwrap();
        std::thread::scope(|scope| {
            let peer = scope.spawn(move || {
                write_public(&mut p, b"{}", &vec![0; calibration_input::Tables::BYTES]).unwrap();
                let binding = ModelBinding { anchor: [1; 32], root: [1; 32], semantics: [2; 32] };
                write_installation(&mut p, &binding, [3; 32], [4; 32]).unwrap();
                for slot in 0..3 {
                    let request = read_request(&mut p, slot).unwrap();
                    assert_eq!(request, [17; 100]);
                    let response = Response {
                        root: C61Commitment::new(vec![[5; 32]]),
                        tokens: [17; 150],
                        nonce: [6; 32],
                        certificate: vec![7; 3 + slot],
                    };
                    response.write(&mut p).unwrap();
                    acceptance_transport::receive(
                        &mut p,
                        *blake3::hash(&response.certificate).as_bytes(),
                        [8; 32],
                    )
                    .unwrap();
                }
            });
            let (candidate, tables) = read_public(&mut v).unwrap();
            assert_eq!(candidate, b"{}");
            assert_eq!(tables.len(), calibration_input::Tables::BYTES);
            v.traffic = m.channel("installation", None);
            read_installation(&mut v).unwrap();
            for slot in 0..3 {
                v.traffic = m.channel("response", Some(slot));
                write_request(&mut v, slot, &[17; 100]).unwrap();
                let response = Response::read(&mut v).unwrap();
                assert_eq!(response.certificate, vec![7; 3 + slot]);
                acceptance_transport::send(
                    &mut v,
                    Some((*blake3::hash(&response.certificate).as_bytes(), [8; 32])),
                )
                .unwrap();
            }
            peer.join().unwrap();
        });
        let r = m.report();
        let initial = (24 + 2 + calibration_input::Tables::BYTES + 136) as u64;
        assert_eq!(r["bytes_to_verifier"], initial + 683 + 684 + 685);
        assert_eq!(r["bytes_from_verifier"], 3 * (416 + 73));
        assert_eq!(
            r["response_charges"][0]["observed_bytes_both_directions"],
            initial + 683 + 416 + 73
        );
        assert_eq!(r["response_charges"][1]["observed_bytes_both_directions"], 684 + 416 + 73);
        assert_eq!(r["response_charges"][2]["observed_bytes_both_directions"], 685 + 416 + 73);
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

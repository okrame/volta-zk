//! Disposable, bounded CPU experiment; never a production security profile.

use super::*;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;
use volta_mac::c7_fp3::{c7_fp3_lift_prover, c7_fp3_lift_verifier};
use volta_pcg::{
    expand_phase_b_production, PhaseAParams, ResponseAuthorizationStore, SessionBinding,
};

fn random_id() -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut id).map_err(|e| e.to_string())?;
    if id == [0; 32] {
        return Err("zero OS identity".into());
    }
    Ok(id)
}

fn binding(session: [u8; 32], capacity: [u8; 32], nonce: [u8; 32]) -> SessionBinding {
    SessionBinding::new(session, capacity, nonce).expect("nonzero local binding")
}

// No Clone, serialization or resume API: dropped state loses the remaining
// keys; the durable root lease prevents recreating its three-slot capacity.
struct State<T> {
    store: ResponseAuthorizationStore,
    session: [u8; 32],
    capacity: [u8; 32],
    predecessor: [u8; 32],
    next: u8,
    per_attempt: usize,
    pool: std::vec::IntoIter<T>,
}

impl<T> State<T> {
    fn new(
        store: ResponseAuthorizationStore,
        session: [u8; 32],
        capacity: [u8; 32],
        per_attempt: usize,
        pool: Vec<T>,
    ) -> Result<Self, String> {
        if pool.len() != 3 * per_attempt {
            return Err(format!(
                "C71 capacity: required {}, available {}",
                3 * per_attempt,
                pool.len()
            ));
        }
        Ok(Self {
            store,
            session,
            capacity,
            predecessor: [0; 32],
            next: 0,
            per_attempt,
            pool: pool.into_iter(),
        })
    }

    fn attempt<R>(
        &mut self,
        f: impl FnOnce(
            AttemptContext,
            &mut std::vec::IntoIter<T>,
        ) -> Result<(R, Option<blake3::Hash>), String>,
    ) -> Result<R, String> {
        if self.next >= 3 {
            return Err("C71 root attempt capacity exhausted".into());
        }
        let slot = self.next;
        self.next += 1;
        let mut nonce = blake3::Hasher::new();
        nonce.update(b"volta-zk/c71/slot/v1");
        nonce.update(&self.session);
        nonce.update(&self.capacity);
        nonce.update(&[slot]);
        let context = AttemptContext {
            session: self.session,
            capacity: self.capacity,
            slot,
            predecessor: self.predecessor,
            nonce: *nonce.finalize().as_bytes(),
        };
        // Remove all material before filesystem/codec/prover work can fail.
        let mut reserved =
            self.pool.by_ref().take(self.per_attempt).collect::<Vec<_>>().into_iter();
        self.store
            .reserve(&binding(self.session, self.capacity, context.nonce))
            .map_err(|e| e.to_string())?;
        if reserved.len() != self.per_attempt {
            return Err(format!(
                "C71 attempt: required {}, available {}",
                self.per_attempt,
                reserved.len()
            ));
        }
        let (result, accepted) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(context, &mut reserved)))
                .map_err(|_| "C71 attempt panicked; reservation burned".to_string())??;
        if let Some(digest) = accepted {
            if reserved.len() != 0 {
                return Err("C71 accepted attempt left unused correlations".into());
            }
            self.predecessor = *digest.as_bytes();
        }
        Ok(result)
    }
}

fn lease(
    store: &ResponseAuthorizationStore,
    root: &C61Commitment,
    session: [u8; 32],
) -> Result<(), String> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"volta-zk/c71/root-capacity/v1");
    hash.update(&root.roots()[0]);
    store
        .reserve(&binding(session, session, *hash.finalize().as_bytes()))
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn lift_header(session: [u8; 32], root: &C61Commitment, count: usize) -> Vec<u8> {
    let mut bytes = b"C71LIFT1".to_vec();
    bytes.extend_from_slice(&session);
    bytes.extend_from_slice(&root.roots()[0]);
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    bytes
}

fn decode_lift(
    bytes: &[u8],
    session: [u8; 32],
    root: &C61Commitment,
    count: usize,
) -> Result<Vec<[Fp; 6]>, String> {
    let header = lift_header(session, root, count);
    if count > 69 || bytes.len() != header.len() + 48 * count || !bytes.starts_with(&header) {
        return Err("C71 lift header/length mismatch".into());
    }
    bytes[header.len()..]
        .chunks_exact(48)
        .map(|record| {
            let mut row = [Fp::ZERO; 6];
            for (out, word) in row.iter_mut().zip(record.chunks_exact(8)) {
                let word = u64::from_le_bytes(word.try_into().unwrap());
                if word >= volta_field::P {
                    return Err("noncanonical lift correction".into());
                }
                *out = Fp::new(word);
            }
            Ok(row)
        })
        .collect()
}

/// Analytic geometry and explicit unknowns, without allocating a witness.
pub fn preflight(n: usize) -> Result<Value, String> {
    let c = matrix_config(n)?;
    let rows: usize = c.round_parameters.iter().map(|r| r.domain_size).sum::<usize>()
        + c.final_round_config().domain_size;
    let mask_cells: usize = c.mask_groups().iter().map(|g| g.width * g.shape.domain_size).sum();
    // ponytail: generous source-layout allowance, not a proved allocator bound;
    // an external 2 GiB address-space/RSS cap remains mandatory for execution.
    let allowance = 128 * (rows + 2 * mask_cells) * 24 + 2 * codec::MAX_BYTES + (64 << 20);
    if allowance > 2 << 30 {
        return Err("C71 geometry exceeds local memory allowance".into());
    }
    Ok(json!({"n": n, "padded_side": 1usize << (c.num_variables / 2),
        "credit": false, "gamma_digest": blake3::hash(&gamma(&c)).to_hex().to_string(),
        "gamma_bytes_hex": gamma(&c).iter().map(|x| format!("{x:02x}")).collect::<String>(),
        "root_attempts": 3, "full_fp3_per_attempt": 3 * (c.num_variables / 2) + 2,
        "svole_per_full_fp3": 9, "alignment_bytes_per_full_fp3": 48,
        "oracle_domain_cells_sum": rows, "mask_domain_cells_sum": mask_cells,
        "memory_allowance_bytes": allowance, "memory_allowance_kind": "analytic diagnostic allowance, not a proved peak",
        "certificate_cap_bytes": codec::MAX_BYTES, "fs_request_limit": request_limit(&c),
        "required_limits": {"process_threads": 2, "rss_and_address_space_bytes": 2u64 << 30, "wall_seconds": 60},
        "complete_fp_multiplications": null, "complete_fp3_multiplications": null,
        "complete_work_admission_bound": "infinity", "missing_work": ["native PCS arithmetic including encoding, folding and verifier", "PCG arithmetic", "basis conversion and codec arithmetic"]}))
}

/// Runs one complete byte-boundary matrix composition with disposable secrets.
/// Call through scripts/run_c71_matrix.py, which enforces process resources.
pub fn run(n: usize, directory: &Path) -> Result<Value, String> {
    let screen = preflight(n)?;
    if rayon::current_num_threads() != 1 {
        return Err("C71 runner needs RAYON_NUM_THREADS=1 (main plus one worker)".into());
    }
    census::start()?;
    let start = Instant::now();
    census::mark("model_setup")?;
    let model_start = Instant::now();
    let weights = (0..n * n).map(|i| ((i * 31 % 65536) as i32 - 32768) as i16).collect();
    let model = Model::new(n, weights)?;
    let model_seconds = model_start.elapsed().as_secs_f64();
    census::mark("connection_pcg")?;
    let setup_start = Instant::now();
    let root = model.root.clone(); // verifier receives only this public model anchor
    let session = random_id()?;
    let prover_store =
        ResponseAuthorizationStore::new(directory.join("prover")).map_err(|e| e.to_string())?;
    let verifier_store =
        ResponseAuthorizationStore::new(directory.join("verifier")).map_err(|e| e.to_string())?;
    lease(&prover_store, &root, session)?;
    lease(&verifier_store, &root, session)?;
    let reopened =
        ResponseAuthorizationStore::new(directory.join("prover")).map_err(|e| e.to_string())?;
    if lease(&reopened, &root, random_id()?).is_ok() {
        return Err("root lease replay accepted".into());
    }
    let h = matrix_config(n)?.num_variables / 2;
    let per_attempt = 3 * h + 2;
    let count = 3 * per_attempt;
    let mut params = PhaseAParams::tiny_for_test(0);
    params.output_sub_equiv = 3 * count;
    params.lpn_n = 512;
    params.ggm_block_size = 64;
    params.ggm_depth = 6;
    // This actual AES/OT path is deliberately tiny: never inherit the source
    // helper's nominal security_bits=128 or production_ready label as credit.
    params.security_bits = 0;
    let mut pools = Vec::new();
    let mut setup_records = Vec::new();
    let mut setup_bytes = 0;
    for _ in 0..3 {
        let pair = expand_phase_b_production(
            &prover_store,
            binding(session, session, random_id()?),
            3 * count,
            0,
            params.clone(),
        )
        .map_err(|e| e.to_string())?
        .expansion;
        if !pair.consistency.ok || pair.setup.role_seeds_shared || pair.setup.delta_serialized {
            return Err("C71 AES setup independence/consistency failed".into());
        }
        setup_bytes += pair.setup.comm.total_bytes;
        setup_records.push(json!({"comm": pair.setup.comm, "timings": pair.timings,
            "params": pair.setup.params, "credit": false}));
        pools.push(pair);
    }
    census::mark("connection_lift")?;
    let delta = Fp3::new(
        pools[0].verifier_delta.c0,
        pools[1].verifier_delta.c0,
        pools[2].verifier_delta.c0,
    );
    if delta == Fp3::ZERO {
        return Err("C71 projected Delta is zero; setup burned".into());
    }
    let mut auths = Vec::new();
    let mut raw_key_rows = Vec::new();
    let mut alignment = lift_header(session, &root, count);
    let alignment_header = alignment.len();
    for _ in 0..count {
        let rows = std::array::from_fn(|_| {
            std::array::from_fn(|lane| pools[lane].prover.subs.pop().unwrap())
        });
        let key_rows = std::array::from_fn(|_| {
            std::array::from_fn(|lane| pools[lane].verifier.sub_keys.pop().unwrap())
        });
        let (corrections, auth) = c7_fp3_lift_prover(rows);
        let bytes: Vec<_> = corrections.into_iter().flat_map(|x| x.value().to_le_bytes()).collect();
        alignment.extend_from_slice(&bytes);
        auths.push(auth);
        raw_key_rows.push(key_rows);
    }
    if pools.iter().any(|p| !p.prover.subs.is_empty() || !p.verifier.sub_keys.is_empty()) {
        return Err("C71 raw AES pool not fully consumed".into());
    }
    drop(pools);
    // Entire framed message crosses the verifier boundary, including the
    // session, root, count and canonical corrections. Prover values do not.
    let decoded = decode_lift(&alignment, session, &root, count)?;
    let keys = raw_key_rows
        .into_iter()
        .zip(decoded)
        .map(|(rows, wire)| c7_fp3_lift_verifier(rows, delta, wire))
        .collect();
    let capacity = *blake3::hash(&alignment).as_bytes();
    let mut provider = State::new(prover_store, session, capacity, per_attempt, auths)?;
    let mut client = State::new(verifier_store, session, capacity, per_attempt, keys)?;
    let setup_seconds = setup_start.elapsed().as_secs_f64();
    let mut attempts = Vec::new();
    let mut certificates = 0;
    for slot in 0..3 {
        if slot == 1 {
            census::mark("abort")?;
            let abort_start = Instant::now();
            // Expose no data, but burn both complete reservations. Predecessor stays accepted.
            provider.attempt(|_, _| Ok(((), None)))?;
            client.attempt(|_, _| Ok(((), None)))?;
            attempts
                .push(json!({"slot": slot, "status": "aborted", "reserved_full_fp3": per_attempt,
                "wire_bytes": 0, "abort_seconds": abort_start.elapsed().as_secs_f64()}));
            continue;
        }
        census::mark("integer_forward")?;
        let input: Vec<i16> = (0..n).map(|j| if slot == 0 { 0 } else { j as i16 - 64 }).collect();
        let forward_start = Instant::now();
        let output: Vec<i64> = model
            .weights
            .chunks_exact(n)
            .map(|row| row.iter().zip(&input).map(|(&w, &x)| i64::from(w) * i64::from(x)).sum())
            .collect();
        let forward_seconds = forward_start.elapsed().as_secs_f64();
        let prove_start = Instant::now();
        let (wire, prove_seconds, encode_seconds, digest) = provider.attempt(|context, pool| {
            let (proof, digest) = matrix_prove(&model, &input, &output, context, pool)?;
            let prove_seconds = prove_start.elapsed().as_secs_f64();
            census::mark("encode")?;
            let encode_start = Instant::now();
            let wire = codec::encode(n, &root, &input, &output, context, &proof)
                .map_err(|e| e.to_string())?;
            Ok(((wire, prove_seconds, encode_start.elapsed().as_secs_f64(), digest), Some(digest)))
        })?;
        census::mark("decode")?;
        let verify_start = Instant::now();
        let (checked, decode_seconds) = client.attempt(|context, pool| {
            let decode_start = Instant::now();
            let proof = codec::decode(n, &root, &input, &output, context, &wire)
                .map_err(|e| e.to_string())?;
            let decode_seconds = decode_start.elapsed().as_secs_f64();
            let checked = matrix_verify(n, &root, &input, &output, context, &proof, delta, pool)?;
            Ok(((checked, decode_seconds), Some(checked)))
        })?;
        if checked != digest {
            return Err("C71 independent transcript mismatch".into());
        }
        certificates += wire.len();
        attempts.push(json!({"slot": slot, "status": "accepted", "wire_bytes": wire.len(),
            "reserved_full_fp3": per_attempt, "forward_seconds": forward_seconds,
            "prove_including_commit_rematerialization_seconds": prove_seconds, "encode_seconds": encode_seconds,
            "decode_seconds": decode_seconds, "decode_and_verify_seconds": verify_start.elapsed().as_secs_f64(),
            "transcript_digest": checked.to_hex().to_string(),
            "packed_weight_full_scans": {"integer_forward": 1, "row_reduction": 1, "commit_rematerialization": 1},
            "packed_weight_bytes_read": 6 * n * n,
            "integer_forward_multiplications": n * n,
            "matrix_reduction_only_fp3_products_prover": n*n + n + 8*((1usize<<h)-1) + 5*h + 1,
            "matrix_reduction_only_fp3_products_verifier": n + 3*((1usize<<h)-1) + 6*h + 3}));
    }
    census::mark("finalization")?;
    let exhaustion = provider.attempt(|_, _| Ok(((), None))).is_err()
        && client.attempt(|_, _| Ok(((), None))).is_err()
        && provider.pool.len() == 0
        && client.pool.len() == 0;
    if !exhaustion {
        return Err("C71 extra attempt or pool residue".into());
    }
    let resources = census::finish()?;
    Ok(json!({"status": "C71_MATRIX_BYTE_REPLAY_PASS", "resources": resources, "credit": false,
        "scope": "complete reduced matrix byte path; physical traffic and security not admitted",
        "preflight": screen, "model_root": root.roots()[0], "model_setup_seconds": model_seconds,
        "connection_and_lift_seconds": setup_seconds, "setup_lanes": setup_records,
        "pcg_diagnostic_params": params, "pcg_security_credit_bits": null,
        "aes_setup_wire_bytes": setup_bytes, "alignment_header_bytes": alignment_header,
        "alignment_corrections_bytes": 48*count, "alignment_wire_bytes": alignment.len(),
        "model_publication_bytes": 32, "certificates_wire_bytes": certificates,
        "total_protocol_wire_bytes": setup_bytes + alignment.len() as u64 + certificates as u64 + 32,
        "wire_scope": "model root, framed real PCG setup, framed lift and self-contained certificates; no network transport used",
        "model_setup_packed_weight_scans": 1, "attempts": attempts,
        "root_lease_reopen_rejected": true, "fourth_attempt_rejected": exhaustion,
        "full_fp3_consumed_or_burned": count, "raw_svole_consumed": 9*count,
        "total_seconds": start.elapsed().as_secs_f64()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_burns_errors_panics_and_failed_replays() {
        let dir = std::env::temp_dir().join(format!("c71-state-{}", rand::random::<u64>()));
        let store = ResponseAuthorizationStore::new(&dir).unwrap();
        let root = C61Commitment::new(vec![[3; 32]]);
        lease(&store, &root, [1; 32]).unwrap();
        assert!(lease(&ResponseAuthorizationStore::new(&dir).unwrap(), &root, [4; 32]).is_err());
        assert!(State::<u8>::new(store.clone(), [1; 32], [2; 32], 2, vec![0; 5]).is_err());
        let mut state = State::new(store, [1; 32], [2; 32], 2, vec![0; 6]).unwrap();
        assert!(state.attempt::<()>(|_, _| Err("malformed".into())).is_err());
        assert_eq!(state.pool.len(), 4);
        assert!(state.attempt::<()>(|_, _| panic!("infallible FS exhaustion")).is_err());
        assert_eq!(state.pool.len(), 2);
        assert_eq!(state.predecessor, [0; 32]);
        state
            .attempt(|ctx, pool| {
                assert_eq!(ctx.slot, 2);
                pool.by_ref().for_each(drop);
                Ok(((), Some(blake3::hash(b"accepted"))))
            })
            .unwrap();
        assert_ne!(state.predecessor, [0; 32]);
        assert!(state.attempt(|_, _| Ok(((), None))).is_err());
        let mut alignment = lift_header([1; 32], &root, 1);
        let offset = alignment.len();
        alignment.extend([0; 48]);
        assert!(decode_lift(&alignment, [1; 32], &root, 1).is_ok());
        assert!(decode_lift(&alignment, [2; 32], &root, 1).is_err());
        assert!(decode_lift(&alignment[..alignment.len() - 1], [1; 32], &root, 1).is_err());
        alignment.push(0);
        assert!(decode_lift(&alignment, [1; 32], &root, 1).is_err());
        alignment.pop();
        alignment[offset..offset + 8].copy_from_slice(&volta_field::P.to_le_bytes());
        assert!(decode_lift(&alignment, [1; 32], &root, 1).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

//! Production provisioning and response-authorization lifecycle for phase B.
//!
//! Role entropy is read independently for each role from [`rand::rngs::OsRng`].
//! On Linux, `rand` 0.8 obtains this randomness through the operating-system
//! `getrandom` interface. The application supplies an authenticated session
//! identity, authenticated channel identity, and verifier-issued single-use
//! response authorization nonce in [`SessionBinding`].
//!
//! [`ResponseAuthorizationStore`] implements burn-before-use: a durable,
//! append-only marker keyed only by the authorization nonce is created and
//! synced before any role entropy is sampled or any correlation is generated.
//! Markers are never deleted on success or failure. Consequently a process
//! kill, protocol abort, reconnect, retry, or resume cannot authorize a second
//! PCG session for the same response.

use crate::phase_b::{bind_role_entropy, expand_phase_b_bound};
use crate::{PhaseAParams, PhaseBError, PhaseBExpansion, SessionBinding};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const BURN_RECORD_MAGIC: &[u8] = b"VOLTA-PCG-AUTH-BURN-v1\n";

#[derive(Clone, Debug)]
pub struct ResponseAuthorizationStore {
    root: PathBuf,
}

/// Evidence that the response authorization was durably burned before setup.
#[derive(Clone, Debug)]
pub struct AuthorizationBurn {
    marker_path: PathBuf,
    pub record_digest: String,
}

impl AuthorizationBurn {
    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductionSetupAudit {
    pub entropy_source: String,
    pub independent_role_entropy_samples: bool,
    pub prover_role_seed_commitment: String,
    pub verifier_role_seed_commitment: String,
    pub role_seed_commitments_distinct: bool,
    pub session_channel_identity_bound: bool,
    pub session_binding_digest: String,
    pub response_authorization_burned_before_setup: bool,
    pub response_authorization_burn_record_digest: String,
    pub burn_on_success_or_abort: bool,
    pub reconnect_retry_resume_allowed: bool,
}

#[derive(Debug)]
pub struct ProductionPhaseBExpansion {
    pub expansion: PhaseBExpansion,
    pub production: ProductionSetupAudit,
}

impl ResponseAuthorizationStore {
    /// Open or create the append-only burn directory. Production deployments
    /// must place it on storage whose durability matches the authorization
    /// service; an unavailable or read-only store fails capability preflight.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PhaseBError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| {
            PhaseBError::new(format!(
                "cannot create response-authorization burn store {}: {error}",
                root.display()
            ))
        })?;
        if !root.is_dir() {
            return Err(PhaseBError::new(format!(
                "response-authorization burn store is not a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Permanently reserve-and-burn an authorization nonce. The marker name is
    /// a nonce-only digest, so reuse is rejected even if a reconnect changes
    /// the claimed session or channel identity. `create_new` is the atomic
    /// concurrency boundary; the file and containing directory are synced
    /// before setup may proceed.
    pub fn reserve(&self, binding: &SessionBinding) -> Result<AuthorizationBurn, PhaseBError> {
        let nonce_digest = digest_parts(
            b"volta-pcg/authorization-nonce/v1",
            &[&binding.response_authorization_nonce],
        );
        let marker_path = self.root.join(format!("{}.burned", hex32(nonce_digest)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&marker_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PhaseBError::new("response-authorization nonce already burned; retry rejected")
            } else {
                PhaseBError::new(format!(
                    "cannot burn response authorization in {}: {error}",
                    marker_path.display()
                ))
            }
        })?;

        let binding_digest = binding.digest_hex();
        let mut record = Vec::with_capacity(BURN_RECORD_MAGIC.len() + binding_digest.len() + 1);
        record.extend_from_slice(BURN_RECORD_MAGIC);
        record.extend_from_slice(binding_digest.as_bytes());
        record.push(b'\n');
        // Once create_new succeeds the nonce is already fail-closed burned.
        // Any later I/O error is returned, but the marker is intentionally not
        // removed and a retry remains forbidden.
        file.write_all(&record).map_err(|error| {
            PhaseBError::new(format!("cannot persist response-authorization burn record: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            PhaseBError::new(format!("cannot sync response-authorization burn record: {error}"))
        })?;
        File::open(&self.root).and_then(|directory| directory.sync_all()).map_err(|error| {
            PhaseBError::new(format!("cannot sync response-authorization burn directory: {error}"))
        })?;

        Ok(AuthorizationBurn {
            marker_path,
            record_digest: hex32(digest_parts(
                b"volta-pcg/authorization-burn-record/v1",
                &[&record],
            )),
        })
    }
}

/// Burn the single-use response authorization, independently sample both role
/// seeds from the OS CSPRNG, bind them to the authenticated identities, and
/// execute phase B. Every error after `reserve` leaves the nonce burned.
pub fn expand_phase_b_production(
    store: &ResponseAuthorizationStore,
    binding: SessionBinding,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> Result<ProductionPhaseBExpansion, PhaseBError> {
    let burn = store.reserve(&binding)?;

    let mut prover_entropy = [0u8; 32];
    let mut verifier_entropy = [0u8; 32];
    OsRng.try_fill_bytes(&mut prover_entropy).map_err(|error| {
        PhaseBError::new(format!("OS entropy unavailable for prover role: {error}"))
    })?;
    OsRng.try_fill_bytes(&mut verifier_entropy).map_err(|error| {
        PhaseBError::new(format!("OS entropy unavailable for verifier role: {error}"))
    })?;
    if prover_entropy == verifier_entropy {
        return Err(PhaseBError::new(
            "OS entropy returned identical prover/verifier role samples; authorization burned",
        ));
    }
    let prover_seed = bind_role_entropy(prover_entropy, &binding, b"prover");
    let verifier_seed = bind_role_entropy(verifier_entropy, &binding, b"verifier");
    prover_entropy.fill(0);
    verifier_entropy.fill(0);

    let prover_commitment = seed_commitment(prover_seed, b"prover");
    let verifier_commitment = seed_commitment(verifier_seed, b"verifier");
    if prover_commitment == verifier_commitment {
        return Err(PhaseBError::new("role-seed commitments collided; authorization burned"));
    }
    let expansion =
        expand_phase_b_bound(prover_seed, verifier_seed, binding, sub_corrs, full_corrs, params)?;
    let production = ProductionSetupAudit {
        entropy_source:
            "rand 0.8 OsRng; Linux OS CSPRNG via getrandom; independent 256-bit role reads".into(),
        independent_role_entropy_samples: true,
        prover_role_seed_commitment: hex32(prover_commitment),
        verifier_role_seed_commitment: hex32(verifier_commitment),
        role_seed_commitments_distinct: true,
        session_channel_identity_bound: true,
        session_binding_digest: binding.digest_hex(),
        response_authorization_burned_before_setup: true,
        response_authorization_burn_record_digest: burn.record_digest,
        burn_on_success_or_abort: true,
        reconnect_retry_resume_allowed: false,
    };
    Ok(ProductionPhaseBExpansion { expansion, production })
}

fn seed_commitment(seed: [u8; 32], role: &[u8]) -> [u8; 32] {
    digest_parts(b"volta-pcg/phase-b/role-seed-commitment/v1", &[role, &seed])
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_store(label: &str) -> (PathBuf, ResponseAuthorizationStore) {
        let serial = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("volta-pcg-{label}-{}-{serial}", std::process::id()));
        let store = ResponseAuthorizationStore::new(&root).unwrap();
        (root, store)
    }

    fn binding(tag: u8) -> SessionBinding {
        SessionBinding::new([tag; 32], [tag.wrapping_add(1); 32], [tag.wrapping_add(2); 32])
            .unwrap()
    }

    #[test]
    fn reconnect_retry_and_nonce_reuse_are_rejected_after_restart() {
        let (root, store) = test_store("restart");
        let first = binding(0x21);
        let burn = store.reserve(&first).unwrap();
        assert!(burn.marker_path().exists());
        drop(store); // Simulate a killed role process after durable reservation.

        let restarted = ResponseAuthorizationStore::new(&root).unwrap();
        let retry = restarted.reserve(&first).unwrap_err();
        assert!(retry.to_string().contains("already burned"));

        let reused_nonce =
            SessionBinding::new([0x41; 32], [0x42; 32], first.response_authorization_nonce)
                .unwrap();
        let reconnect = restarted.reserve(&reused_nonce).unwrap_err();
        assert!(reconnect.to_string().contains("already burned"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abort_burns_nonce_and_fresh_restart_correlations_do_not_repeat() {
        let (root, store) = test_store("abort-non-reuse");
        let aborted = binding(0x31);
        let bad_params = PhaseAParams::tiny_for_test(58);
        let error = expand_phase_b_production(&store, aborted, 47, 5, bad_params).unwrap_err();
        assert!(error.to_string().contains("params/count mismatch"));
        assert!(store.reserve(&aborted).unwrap_err().to_string().contains("already burned"));

        let params = PhaseAParams::tiny_for_test(58);
        let first =
            expand_phase_b_production(&store, binding(0x51), 48, 5, params.clone()).unwrap();
        drop(store);
        let restarted = ResponseAuthorizationStore::new(&root).unwrap();
        let second = expand_phase_b_production(&restarted, binding(0x61), 48, 5, params).unwrap();
        assert_ne!(
            first.production.prover_role_seed_commitment,
            second.production.prover_role_seed_commitment
        );
        assert_ne!(
            first.production.verifier_role_seed_commitment,
            second.production.verifier_role_seed_commitment
        );
        assert_ne!(first.expansion.prover.subs[0].r, second.expansion.prover.subs[0].r);
        assert!(first.production.response_authorization_burned_before_setup);
        assert!(second.production.response_authorization_burned_before_setup);
        assert!(!first.production.reconnect_retry_resume_allowed);
        std::fs::remove_dir_all(root).unwrap();
    }
}

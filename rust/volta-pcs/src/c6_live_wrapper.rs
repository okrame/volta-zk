//! Same-attempt provider bridge from live C6 owners to the six packed roots.
//!
//! This module deliberately has no constructor from roots.  A
//! [`C6LiveWrapperRootBinding`] exists only after the exact cache, residual
//! and hidden-`u` sources have been validated, committed and fixed in the
//! response transcript.

use std::fmt;

use rand::{rngs::OsRng, RngCore};
use std::path::Path;
use volta_accel::{Backend, BackendKind};
use volta_field::{Fp2, FpStream};
use volta_mac::Transcript;
use volta_proto::{
    C6PairedResidualAuxiliaryWitness, C6PairedResidualClosureWitness, C6PairedResidualLeafWitness,
    C6ResidualFusedWitnessView, C6ResidualRelationManifest, C6ResidualRelationRootBound,
};

use crate::c6_hidden_u::{C6HiddenUFamily, C6HiddenUFamilyWitness, C6HiddenULayout};
use crate::c6_persistent_cache::{
    C6PersistentCacheLayout, C6PersistentCacheStateWitness, C6PersistentCacheStaticProfile,
};
use crate::c6_wrapper_pcs::{
    bind_production_c6_residual_relation_roots, commit_c6_cache_state_cohort,
    commit_c6_wrapper_cohort, fix_production_c6_wrapper_commitments, production_c6_wrapper_specs,
    C6CacheStateDescriptors, C6CommittedWrapperCohort, C6FixedWrapperCommitments,
    C6WrapperCohortSpec, C6WrapperDigest, C6WrapperOracleKind, C6WrapperSlotWitness,
    C6_DELTA_RESIDUAL_COHORT_ID, C6_HIDDEN_U_EMBED_COHORT_ID, C6_HIDDEN_U_WEIGHTS_COHORT_ID,
    C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID, C6_WRAPPER_AUXILIARY_COHORT_ID,
};
use crate::c6_wrapper_persisted::{
    commit_production_c6_wrapper_cohort_cuda, C6PersistedWrapperCohort, C6PersistedWrapperMetrics,
};
use crate::x4::cuda_v4::X4bCudaCommitMetricsV4;

const LIVE_SOURCE_BINDING_DOMAIN: &str = "volta-zk/c6/live-wrapper-source-binding/v1";
const MASK_SEED_COMMITMENT_DOMAIN: &str = "volta-zk/c6/live-wrapper-mask-seed/v1";

type Result<T> = std::result::Result<T, C6LiveWrapperError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6LiveWrapperError(String);

impl C6LiveWrapperError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6LiveWrapperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6LiveWrapperError {}

/// Fresh provider-secret entropy for every strict-rate wrapper upper half.
///
/// Production callers should use [`Self::random`].  `from_attempt_secret`
/// exists for a durable private-attempt journal: the secret must be freshly
/// sampled before the response and must never be derived from verifier
/// challenges or serialized in the certificate.
pub struct C6LiveWrapperMaskSeed([u8; 32]);

impl fmt::Debug for C6LiveWrapperMaskSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("C6LiveWrapperMaskSeed([REDACTED])")
    }
}

impl C6LiveWrapperMaskSeed {
    pub fn random() -> Self {
        loop {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            if seed != [0; 32] {
                return Self(seed);
            }
        }
    }

    pub fn from_attempt_secret(seed: [u8; 32]) -> Result<Self> {
        if seed == [0; 32] {
            return Err(C6LiveWrapperError::new("zero C6 live-wrapper mask seed"));
        }
        Ok(Self(seed))
    }

    pub fn commitment(&self) -> C6WrapperDigest {
        let mut hasher = blake3::Hasher::new_derive_key(MASK_SEED_COMMITMENT_DOMAIN);
        hasher.update(&self.0);
        *hasher.finalize().as_bytes()
    }
}

/// Exact live owners required before any retained C6 response challenge.
/// Cache states are moved into this object so committing them cannot silently
/// switch to another state after validation.  Other witnesses are borrowed
/// because their downstream sumchecks consume the same immutable objects.
pub struct C6LiveWrapperSources<'a> {
    statement_digest: C6WrapperDigest,
    cache_binding_digest: C6WrapperDigest,
    cache_layout: C6PersistentCacheLayout,
    cache_descriptors: C6CacheStateDescriptors,
    predecessor: C6PersistentCacheStateWitness,
    successor: C6PersistentCacheStateWitness,
    old_len: u16,
    new_len: u16,
    hidden_weights: &'a C6HiddenUFamilyWitness,
    hidden_embed: &'a C6HiddenUFamilyWitness,
    residual_manifest: &'a C6ResidualRelationManifest,
    residual_leaf: &'a C6PairedResidualLeafWitness,
    residual_closure: &'a C6PairedResidualClosureWitness,
    residual_auxiliary: &'a C6PairedResidualAuxiliaryWitness,
    production: bool,
}

impl<'a> C6LiveWrapperSources<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn production(
        statement_digest: C6WrapperDigest,
        cache_profile: &C6PersistentCacheStaticProfile,
        predecessor: C6PersistentCacheStateWitness,
        successor: C6PersistentCacheStateWitness,
        old_len: u16,
        new_len: u16,
        hidden_weights: &'a C6HiddenUFamilyWitness,
        hidden_embed: &'a C6HiddenUFamilyWitness,
        residual_manifest: &'a C6ResidualRelationManifest,
        residual_leaf: &'a C6PairedResidualLeafWitness,
        residual_closure: &'a C6PairedResidualClosureWitness,
        residual_auxiliary: &'a C6PairedResidualAuxiliaryWitness,
    ) -> Result<Self> {
        cache_profile.validate().map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        let cache_binding_digest =
            cache_profile.digest().map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        let cache_descriptors = C6CacheStateDescriptors::from_persistent_profile(cache_profile)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        let sources = Self {
            statement_digest,
            cache_binding_digest,
            cache_layout: C6PersistentCacheLayout::production(),
            cache_descriptors,
            predecessor,
            successor,
            old_len,
            new_len,
            hidden_weights,
            hidden_embed,
            residual_manifest,
            residual_leaf,
            residual_closure,
            residual_auxiliary,
            production: true,
        };
        sources.validate(&production_c6_wrapper_specs())?;
        Ok(sources)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn scaled(
        statement_digest: C6WrapperDigest,
        cache_binding_digest: C6WrapperDigest,
        cache_layout: C6PersistentCacheLayout,
        cache_descriptors: C6CacheStateDescriptors,
        predecessor: C6PersistentCacheStateWitness,
        successor: C6PersistentCacheStateWitness,
        old_len: u16,
        new_len: u16,
        hidden_weights: &'a C6HiddenUFamilyWitness,
        hidden_embed: &'a C6HiddenUFamilyWitness,
        residual_manifest: &'a C6ResidualRelationManifest,
        residual_leaf: &'a C6PairedResidualLeafWitness,
        residual_closure: &'a C6PairedResidualClosureWitness,
        residual_auxiliary: &'a C6PairedResidualAuxiliaryWitness,
        specs: &[C6WrapperCohortSpec; 6],
    ) -> Result<Self> {
        let sources = Self {
            statement_digest,
            cache_binding_digest,
            cache_layout,
            cache_descriptors,
            predecessor,
            successor,
            old_len,
            new_len,
            hidden_weights,
            hidden_embed,
            residual_manifest,
            residual_leaf,
            residual_closure,
            residual_auxiliary,
            production: false,
        };
        sources.validate(specs)?;
        Ok(sources)
    }

    fn validate(&self, specs: &[C6WrapperCohortSpec; 6]) -> Result<C6ResidualFusedWitnessView<'_>> {
        validate_live_specs(specs)?;
        if self.statement_digest == [0; 32] || self.cache_binding_digest == [0; 32] {
            return Err(C6LiveWrapperError::new("zero C6 live-wrapper statement/cache binding"));
        }
        self.predecessor
            .validate_canonical(self.cache_layout, self.old_len)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        self.successor
            .validate_canonical(self.cache_layout, self.new_len)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        if self.old_len > self.new_len {
            return Err(C6LiveWrapperError::new("C6 live-wrapper cache length regressed"));
        }
        let cache_entries = self
            .cache_layout
            .padded_entries()
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        if cache_entries != checked_pow2(specs[0].payload_log2)? {
            return Err(C6LiveWrapperError::new("C6 live-wrapper cache/spec geometry mismatch"));
        }
        if self.hidden_weights.layout().family != C6HiddenUFamily::Weights
            || self.hidden_embed.layout().family != C6HiddenUFamily::Embed
            || self.hidden_weights.layout().padded_entries() != checked_pow2(specs[3].payload_log2)?
            || self.hidden_embed.layout().padded_entries() != checked_pow2(specs[4].payload_log2)?
        {
            return Err(C6LiveWrapperError::new("C6 live-wrapper hidden-u owner mismatch"));
        }
        if self.residual_manifest.leaf_log2() != specs[2].payload_log2
            || self
                .residual_manifest
                .auxiliary_log2()
                .checked_add(1)
                .ok_or_else(|| C6LiveWrapperError::new("C6 auxiliary wrapper log overflows"))?
                != specs[5].payload_log2
        {
            return Err(C6LiveWrapperError::new("C6 live-wrapper residual/spec geometry mismatch"));
        }
        if self.production
            && (self.cache_layout != C6PersistentCacheLayout::production()
                || self.hidden_weights.layout() != C6HiddenULayout::production_weights()
                || self.hidden_embed.layout() != C6HiddenULayout::production_embed()
                || self.residual_leaf.production_allocation_binding_digest().is_none()
                || !self.residual_manifest.is_production_geometry()
                || *specs != production_c6_wrapper_specs())
        {
            return Err(C6LiveWrapperError::new(
                "C6 live-wrapper production source/profile mismatch",
            ));
        }
        C6ResidualFusedWitnessView::new(
            self.residual_manifest,
            self.residual_leaf,
            self.residual_closure,
            self.residual_auxiliary,
        )
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))
    }
}

/// Six committed cohorts plus the transcript-fixed token that proves they
/// came from one validated live-source materialization.
pub struct C6LiveWrapperRootBinding {
    cohorts: Vec<C6CommittedWrapperCohort>,
    fixed: C6FixedWrapperCommitments,
    source_binding_digest: C6WrapperDigest,
    paired_source_digest: C6WrapperDigest,
    residual_manifest_digest: C6WrapperDigest,
    residual_view_digest: C6WrapperDigest,
    mask_seed_commitment: C6WrapperDigest,
}

/// Production counterpart which owns only create-new persisted/CUDA opening
/// sources. It has no conversion from resident cohorts or external roots.
pub struct C6PersistedLiveWrapperRootBinding {
    cohorts: Vec<C6PersistedWrapperCohort>,
    fixed: C6FixedWrapperCommitments,
    source_binding_digest: C6WrapperDigest,
    paired_source_digest: C6WrapperDigest,
    residual_manifest_digest: C6WrapperDigest,
    residual_view_digest: C6WrapperDigest,
    mask_seed_commitment: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    commit_metrics: X4bCudaCommitMetricsV4,
    persisted_metrics: C6PersistedWrapperMetrics,
}

impl C6PersistedLiveWrapperRootBinding {
    pub fn cohorts(&self) -> &[C6PersistedWrapperCohort] {
        &self.cohorts
    }

    pub fn fixed(&self) -> &C6FixedWrapperCommitments {
        &self.fixed
    }

    pub fn source_binding_digest(&self) -> C6WrapperDigest {
        self.source_binding_digest
    }

    pub fn session_digest(&self) -> C6WrapperDigest {
        self.session_digest
    }

    pub fn commit_metrics(&self) -> &X4bCudaCommitMetricsV4 {
        &self.commit_metrics
    }

    pub fn persisted_metrics(&self) -> C6PersistedWrapperMetrics {
        self.persisted_metrics
    }

    pub fn mask_seed_commitment(&self) -> C6WrapperDigest {
        self.mask_seed_commitment
    }

    pub fn bind_residual_relation(
        &self,
        manifest: C6ResidualRelationManifest,
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<C6ResidualRelationRootBound> {
        let view = C6ResidualFusedWitnessView::new(&manifest, leaf, closure, auxiliary)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        if manifest.digest() != self.residual_manifest_digest
            || view.digest() != self.residual_view_digest
            || leaf.paired_source_digest() != self.paired_source_digest
        {
            return Err(C6LiveWrapperError::new(
                "C6 residual owners differ from persisted live-wrapper roots",
            ));
        }
        bind_production_c6_residual_relation_roots(&self.fixed, manifest)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))
    }
}

impl C6LiveWrapperRootBinding {
    pub fn cohorts(&self) -> &[C6CommittedWrapperCohort] {
        &self.cohorts
    }

    pub fn fixed(&self) -> &C6FixedWrapperCommitments {
        &self.fixed
    }

    pub fn source_binding_digest(&self) -> C6WrapperDigest {
        self.source_binding_digest
    }

    pub fn paired_source_digest(&self) -> C6WrapperDigest {
        self.paired_source_digest
    }

    pub fn mask_seed_commitment(&self) -> C6WrapperDigest {
        self.mask_seed_commitment
    }

    /// Join the fixed roots to the same residual owners that were committed.
    /// A caller cannot substitute a second paired witness between root
    /// materialization and the direct C6RSC3 prover.
    pub fn bind_residual_relation(
        &self,
        manifest: C6ResidualRelationManifest,
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<C6ResidualRelationRootBound> {
        let view = C6ResidualFusedWitnessView::new(&manifest, leaf, closure, auxiliary)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        if manifest.digest() != self.residual_manifest_digest
            || view.digest() != self.residual_view_digest
            || leaf.paired_source_digest() != self.paired_source_digest
        {
            return Err(C6LiveWrapperError::new(
                "C6 residual owners differ from the live-wrapper root materialization",
            ));
        }
        bind_production_c6_residual_relation_roots(&self.fixed, manifest)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))
    }
}

/// Materialize and fix the exact six production roots before `chi`.
pub fn materialize_production_c6_live_wrapper_roots(
    sources: C6LiveWrapperSources<'_>,
    mask_seed: C6LiveWrapperMaskSeed,
    transcript: &mut Transcript,
) -> Result<C6LiveWrapperRootBinding> {
    let specs = production_c6_wrapper_specs();
    if !sources.production {
        return Err(C6LiveWrapperError::new("C6 production materializer received scaled sources"));
    }
    let materialized = materialize_live_wrapper_cohorts(sources, &mask_seed, specs)?;
    let commitments =
        materialized.cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    let fixed = fix_production_c6_wrapper_commitments(
        materialized.statement_digest,
        &materialized.cache_descriptors,
        &commitments,
        transcript,
    )
    .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
    let source_binding_digest = live_source_binding_digest(
        materialized.statement_digest,
        materialized.cache_binding_digest,
        materialized.old_len,
        materialized.new_len,
        materialized.residual_manifest_digest,
        materialized.residual_view_digest,
        materialized.paired_source_digest,
        materialized.hidden_witness_digests,
        mask_seed.commitment(),
        fixed.binding_digest(),
    );
    Ok(C6LiveWrapperRootBinding {
        cohorts: materialized.cohorts,
        fixed,
        source_binding_digest,
        paired_source_digest: materialized.paired_source_digest,
        residual_manifest_digest: materialized.residual_manifest_digest,
        residual_view_digest: materialized.residual_view_digest,
        mask_seed_commitment: mask_seed.commitment(),
    })
}

/// Commit the exact six production cohorts one at a time through the
/// fail-closed CUDA/persisted backend, then fix all roots before `chi`.
#[allow(clippy::too_many_arguments)]
pub fn materialize_production_c6_live_wrapper_roots_cuda(
    sources: C6LiveWrapperSources<'_>,
    mask_seed: C6LiveWrapperMaskSeed,
    backend: &mut Backend,
    spill_root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<C6PersistedLiveWrapperRootBinding> {
    if backend.kind() == BackendKind::Cpu {
        return Err(C6LiveWrapperError::new("C6 production live-wrapper refuses CPU backend"));
    }
    if session_digest == [0; 32] || !sources.production {
        return Err(C6LiveWrapperError::new("C6 persisted live-wrapper session/profile mismatch"));
    }
    let specs = production_c6_wrapper_specs();
    let residual_view_digest = sources.validate(&specs)?.digest();
    let residual_manifest_digest = sources.residual_manifest.digest();
    let paired_source_digest = sources.residual_leaf.paired_source_digest();
    let hidden_witness_digests = [
        sources.hidden_weights.reference_witness_digest(),
        sources.hidden_embed.reference_witness_digest(),
    ];
    let statement_digest = sources.statement_digest;
    let cache_binding_digest = sources.cache_binding_digest;
    let cache_descriptors = sources.cache_descriptors.clone();
    let old_len = sources.old_len;
    let new_len = sources.new_len;
    let mask_seed_commitment = mask_seed.commitment();
    let mut cohorts = Vec::with_capacity(specs.len());
    let mut commit_metrics = X4bCudaCommitMetricsV4::default();
    let mut persisted_metrics = C6PersistedWrapperMetrics::default();
    let mut commit_group = |index: usize, slots: Vec<C6WrapperSlotWitness>| -> Result<()> {
        if slots.len() != usize::from(specs[index].slot_count) {
            return Err(C6LiveWrapperError::new(format!(
                "C6 persisted live cohort {index} slot census mismatch"
            )));
        }
        let descriptors = (index < 2).then_some(&cache_descriptors);
        let (cohort, metrics) = commit_production_c6_wrapper_cohort_cuda(
            backend,
            statement_digest,
            specs[index],
            slots,
            descriptors,
            spill_root.as_ref(),
            session_digest,
            index as u64,
        )
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        commit_metrics
            .include(&metrics)
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        persisted_metrics
            .include(cohort.metrics())
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        cohorts.push(cohort);
        Ok(())
    };

    for (index, state) in [sources.predecessor, sources.successor].into_iter().enumerate() {
        let slots = state
            .slots
            .into_iter()
            .enumerate()
            .map(|(slot, witness)| C6WrapperSlotWitness::Witness {
                witness,
                zk_mask: wrapper_mask_table(
                    &mask_seed,
                    specs[index].cohort_id,
                    slot as u16,
                    checked_pow2(specs[index].payload_log2).expect("validated production spec"),
                ),
            })
            .collect();
        commit_group(index, slots)?;
    }

    let mut residual_slots = sources
        .residual_leaf
        .materialize_padded_columns(u32::from(specs[2].payload_log2))
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?
        .into_iter()
        .enumerate()
        .map(|(slot, witness)| C6WrapperSlotWitness::Witness {
            witness,
            zk_mask: wrapper_mask_table(
                &mask_seed,
                specs[2].cohort_id,
                slot as u16,
                checked_pow2(specs[2].payload_log2).expect("validated production spec"),
            ),
        })
        .collect::<Vec<_>>();
    residual_slots.push(C6WrapperSlotWitness::Witness {
        witness: sources
            .residual_closure
            .materialize_padded(u32::from(specs[2].payload_log2))
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?,
        zk_mask: wrapper_mask_table(
            &mask_seed,
            specs[2].cohort_id,
            7,
            checked_pow2(specs[2].payload_log2).expect("validated production spec"),
        ),
    });
    commit_group(2, residual_slots)?;

    for (index, hidden) in [(3usize, sources.hidden_weights), (4usize, sources.hidden_embed)] {
        let payload_len = checked_pow2(specs[index].payload_log2)?;
        let mut slots = Vec::with_capacity(usize::from(specs[index].slot_count));
        slots.push(C6WrapperSlotWitness::Witness {
            witness: hidden
                .materialize_padded_oracle()
                .map_err(|error| C6LiveWrapperError::new(error.to_string()))?,
            zk_mask: wrapper_mask_table(&mask_seed, specs[index].cohort_id, 0, payload_len),
        });
        for slot in 1..specs[index].slot_count {
            slots.push(C6WrapperSlotWitness::Witness {
                witness: vec![Fp2::ZERO; payload_len],
                zk_mask: wrapper_mask_table(&mask_seed, specs[index].cohort_id, slot, payload_len),
            });
        }
        commit_group(index, slots)?;
    }

    let semantic = sources
        .residual_auxiliary
        .materialize_semantic_halves_at_log2(sources.residual_manifest.auxiliary_log2())
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
    let semantic_len = checked_pow2(sources.residual_manifest.auxiliary_log2())?;
    let encoded_semantic_len = semantic_len
        .checked_mul(2)
        .ok_or_else(|| C6LiveWrapperError::new("C6 auxiliary encoded length overflow"))?;
    let mut auxiliary_slots = semantic
        .into_iter()
        .enumerate()
        .map(|(slot, lower)| {
            let mut evaluations = Vec::with_capacity(encoded_semantic_len);
            evaluations.extend(lower);
            evaluations.extend(wrapper_mask_table(
                &mask_seed,
                specs[5].cohort_id,
                slot as u16,
                semantic_len,
            ));
            C6WrapperSlotWitness::Auxiliary { evaluations }
        })
        .collect::<Vec<_>>();
    let auxiliary_len = checked_pow2(specs[5].payload_log2)?;
    auxiliary_slots.extend(
        (16..specs[5].slot_count).map(|_| C6WrapperSlotWitness::Auxiliary {
            evaluations: vec![Fp2::ZERO; auxiliary_len],
        }),
    );
    commit_group(5, auxiliary_slots)?;
    drop(commit_group);

    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    let fixed = fix_production_c6_wrapper_commitments(
        statement_digest,
        &cache_descriptors,
        &commitments,
        transcript,
    )
    .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
    let source_binding_digest = live_source_binding_digest(
        statement_digest,
        cache_binding_digest,
        old_len,
        new_len,
        residual_manifest_digest,
        residual_view_digest,
        paired_source_digest,
        hidden_witness_digests,
        mask_seed_commitment,
        fixed.binding_digest(),
    );
    Ok(C6PersistedLiveWrapperRootBinding {
        cohorts,
        fixed,
        source_binding_digest,
        paired_source_digest,
        residual_manifest_digest,
        residual_view_digest,
        mask_seed_commitment,
        session_digest,
        commit_metrics,
        persisted_metrics,
    })
}

struct MaterializedLiveWrapperCohorts {
    statement_digest: C6WrapperDigest,
    cache_binding_digest: C6WrapperDigest,
    cache_descriptors: C6CacheStateDescriptors,
    old_len: u16,
    new_len: u16,
    residual_manifest_digest: C6WrapperDigest,
    residual_view_digest: C6WrapperDigest,
    paired_source_digest: C6WrapperDigest,
    hidden_witness_digests: [C6WrapperDigest; 2],
    cohorts: Vec<C6CommittedWrapperCohort>,
}

fn materialize_live_wrapper_cohorts(
    sources: C6LiveWrapperSources<'_>,
    mask_seed: &C6LiveWrapperMaskSeed,
    specs: [C6WrapperCohortSpec; 6],
) -> Result<MaterializedLiveWrapperCohorts> {
    let residual_view = sources.validate(&specs)?;
    let residual_view_digest = residual_view.digest();
    let residual_manifest_digest = sources.residual_manifest.digest();
    let paired_source_digest = sources.residual_leaf.paired_source_digest();
    let hidden_witness_digests = [
        sources.hidden_weights.reference_witness_digest(),
        sources.hidden_embed.reference_witness_digest(),
    ];

    let mut slot_groups: [Vec<C6WrapperSlotWitness>; 6] =
        std::array::from_fn(|index| Vec::with_capacity(usize::from(specs[index].slot_count)));
    for (group, state) in [sources.predecessor, sources.successor].into_iter().enumerate() {
        for (slot, witness) in state.slots.into_iter().enumerate() {
            slot_groups[group].push(C6WrapperSlotWitness::Witness {
                witness,
                zk_mask: wrapper_mask_table(
                    mask_seed,
                    specs[group].cohort_id,
                    slot as u16,
                    checked_pow2(specs[group].payload_log2)?,
                ),
            });
        }
    }

    let padded_leaf = sources
        .residual_leaf
        .materialize_padded_columns(u32::from(specs[2].payload_log2))
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
    for (slot, witness) in padded_leaf.into_iter().enumerate() {
        slot_groups[2].push(C6WrapperSlotWitness::Witness {
            witness,
            zk_mask: wrapper_mask_table(
                mask_seed,
                specs[2].cohort_id,
                slot as u16,
                checked_pow2(specs[2].payload_log2)?,
            ),
        });
    }
    slot_groups[2].push(C6WrapperSlotWitness::Witness {
        witness: sources
            .residual_closure
            .materialize_padded(u32::from(specs[2].payload_log2))
            .map_err(|error| C6LiveWrapperError::new(error.to_string()))?,
        zk_mask: wrapper_mask_table(
            mask_seed,
            specs[2].cohort_id,
            7,
            checked_pow2(specs[2].payload_log2)?,
        ),
    });

    for (group, hidden) in [(3usize, sources.hidden_weights), (4usize, sources.hidden_embed)] {
        let payload_len = checked_pow2(specs[group].payload_log2)?;
        slot_groups[group].push(C6WrapperSlotWitness::Witness {
            witness: hidden
                .materialize_padded_oracle()
                .map_err(|error| C6LiveWrapperError::new(error.to_string()))?,
            zk_mask: wrapper_mask_table(mask_seed, specs[group].cohort_id, 0, payload_len),
        });
        for slot in 1..specs[group].slot_count {
            slot_groups[group].push(C6WrapperSlotWitness::Witness {
                witness: vec![Fp2::ZERO; payload_len],
                zk_mask: wrapper_mask_table(mask_seed, specs[group].cohort_id, slot, payload_len),
            });
        }
    }

    let semantic = sources
        .residual_auxiliary
        .materialize_semantic_halves_at_log2(sources.residual_manifest.auxiliary_log2())
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
    let semantic_len = checked_pow2(sources.residual_manifest.auxiliary_log2())?;
    for (slot, lower) in semantic.into_iter().enumerate() {
        let mut evaluations = Vec::with_capacity(
            semantic_len
                .checked_mul(2)
                .ok_or_else(|| C6LiveWrapperError::new("C6 auxiliary table length overflows"))?,
        );
        evaluations.extend(lower);
        evaluations.extend(wrapper_mask_table(
            mask_seed,
            specs[5].cohort_id,
            slot as u16,
            semantic_len,
        ));
        slot_groups[5].push(C6WrapperSlotWitness::Auxiliary { evaluations });
    }
    let auxiliary_len = checked_pow2(specs[5].payload_log2)?;
    for _slot in 16..specs[5].slot_count {
        slot_groups[5]
            .push(C6WrapperSlotWitness::Auxiliary { evaluations: vec![Fp2::ZERO; auxiliary_len] });
    }

    let mut cohorts = Vec::with_capacity(specs.len());
    for (index, (spec, slots)) in specs.into_iter().zip(slot_groups).enumerate() {
        if slots.len() != usize::from(spec.slot_count) {
            return Err(C6LiveWrapperError::new(format!(
                "C6 live-wrapper cohort {index} slot census mismatch"
            )));
        }
        let cohort = if index < 2 {
            commit_c6_cache_state_cohort(
                sources.statement_digest,
                spec,
                slots,
                &sources.cache_descriptors,
            )
        } else {
            commit_c6_wrapper_cohort(sources.statement_digest, spec, slots)
        }
        .map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        cohorts.push(cohort);
    }
    Ok(MaterializedLiveWrapperCohorts {
        statement_digest: sources.statement_digest,
        cache_binding_digest: sources.cache_binding_digest,
        cache_descriptors: sources.cache_descriptors,
        old_len: sources.old_len,
        new_len: sources.new_len,
        residual_manifest_digest,
        residual_view_digest,
        paired_source_digest,
        hidden_witness_digests,
        cohorts,
    })
}

fn validate_live_specs(specs: &[C6WrapperCohortSpec; 6]) -> Result<()> {
    let expected = [
        (C6_PREDECESSOR_CACHE_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_SUCCESSOR_CACHE_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_DELTA_RESIDUAL_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_HIDDEN_U_EMBED_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_WRAPPER_AUXILIARY_COHORT_ID, C6WrapperOracleKind::Auxiliary, 32),
    ];
    for (spec, (cohort_id, oracle_kind, slot_count)) in specs.iter().zip(expected) {
        spec.validate().map_err(|error| C6LiveWrapperError::new(error.to_string()))?;
        if spec.cohort_id != cohort_id
            || spec.oracle_kind != oracle_kind
            || spec.slot_count != slot_count
        {
            return Err(C6LiveWrapperError::new("C6 live-wrapper cohort profile mismatch"));
        }
    }
    Ok(())
}

fn wrapper_mask_table(
    seed: &C6LiveWrapperMaskSeed,
    cohort_id: u32,
    slot: u16,
    len: usize,
) -> Vec<Fp2> {
    let domain = (u64::from(cohort_id) << 16) | u64::from(slot);
    let mut stream = FpStream::domain_separated(seed.0, domain);
    (0..len).map(|_| stream.next_fp2()).collect()
}

fn checked_pow2(log2: u8) -> Result<usize> {
    1usize
        .checked_shl(u32::from(log2))
        .ok_or_else(|| C6LiveWrapperError::new("C6 live-wrapper dimension exceeds usize"))
}

#[allow(clippy::too_many_arguments)]
fn live_source_binding_digest(
    statement_digest: C6WrapperDigest,
    cache_binding_digest: C6WrapperDigest,
    old_len: u16,
    new_len: u16,
    residual_manifest_digest: C6WrapperDigest,
    residual_view_digest: C6WrapperDigest,
    paired_source_digest: C6WrapperDigest,
    hidden_witness_digests: [C6WrapperDigest; 2],
    mask_seed_commitment: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
) -> C6WrapperDigest {
    let mut hasher = blake3::Hasher::new_derive_key(LIVE_SOURCE_BINDING_DOMAIN);
    hasher.update(&statement_digest);
    hasher.update(&cache_binding_digest);
    hasher.update(&old_len.to_le_bytes());
    hasher.update(&new_len.to_le_bytes());
    hasher.update(&residual_manifest_digest);
    hasher.update(&residual_view_digest);
    hasher.update(&paired_source_digest);
    for digest in hidden_witness_digests {
        hasher.update(&digest);
    }
    hasher.update(&mask_seed_commitment);
    hasher.update(&fixed_roots_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(all(test, feature = "c6-trace"))]
mod tests {
    use super::*;
    use crate::c6_hidden_u::C6HiddenUFamilyWitness;
    use crate::c6_persistent_cache::{C6CacheCell, C6CacheSlotKind};
    use crate::c6_wrapper_pcs::fix_test_c6_wrapper_commitments;
    use crate::ligero::LigeroParams;
    use volta_field::Fp;
    use volta_proto::build_c6_residual_fused_scaled_fixture;

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(Fp::new(value))
    }

    fn hidden_witness(layout: C6HiddenULayout, base: u64) -> C6HiddenUFamilyWitness {
        let u_c = (0..layout.msg_len()).map(|index| fp2(base + index as u64)).collect();
        let u_gs = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.msg_len())
                    .map(|index| fp2(base + 100 + 10 * claim as u64 + index as u64))
                    .collect()
            })
            .collect();
        let q_cols = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.cols())
                    .map(|index| fp2(base + 200 + 10 * claim as u64 + index as u64))
                    .collect()
            })
            .collect();
        C6HiddenUFamilyWitness::new(layout, u_c, u_gs, q_cols).unwrap()
    }

    fn hidden_layout(family: C6HiddenUFamily) -> C6HiddenULayout {
        let (claim_count, vector_capacity) = match family {
            C6HiddenUFamily::Weights => (2, 4),
            C6HiddenUFamily::Embed => (1, 2),
        };
        C6HiddenULayout {
            family,
            params: LigeroParams { rows: 4, col_bits: 2, pad: 2, code_bits: 3, n_queries: 2 },
            claim_count,
            vector_capacity,
            vector_stride: 8,
        }
    }

    #[test]
    fn scaled_live_sources_materialize_all_six_exact_cohorts_before_root_fixing() {
        let fixture = build_c6_residual_fused_scaled_fixture().unwrap();
        let cache_layout = C6PersistentCacheLayout {
            layers: 1,
            capacity_tokens: 8,
            width: 2,
            padded_layers: 4,
            padded_width: 8,
        };
        let mut predecessor = C6PersistentCacheStateWitness::zero(cache_layout).unwrap();
        for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
            for position in 0..2u16 {
                for channel in 0..2u16 {
                    predecessor
                        .set(
                            cache_layout,
                            C6CacheCell { kind, layer: 0, position, channel },
                            fp2(10 + kind as u64 * 100 + position as u64 * 10 + channel as u64),
                        )
                        .unwrap();
                }
            }
        }
        let mut successor = predecessor.clone();
        for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
            for channel in 0..2u16 {
                successor
                    .set(
                        cache_layout,
                        C6CacheCell { kind, layer: 0, position: 2, channel },
                        fp2(500 + kind as u64 * 100 + channel as u64),
                    )
                    .unwrap();
            }
        }
        let weights = hidden_witness(hidden_layout(C6HiddenUFamily::Weights), 1_000);
        let embed = hidden_witness(hidden_layout(C6HiddenUFamily::Embed), 2_000);
        let specs = [
            C6WrapperCohortSpec {
                cohort_id: C6_PREDECESSOR_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 8,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_SUCCESSOR_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 8,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_DELTA_RESIDUAL_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: fixture.manifest().leaf_log2(),
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_WEIGHTS_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 5,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_EMBED_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 4,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: fixture.manifest().auxiliary_log2() + 1,
                slot_count: 32,
            },
        ];
        let cache_descriptors = C6CacheStateDescriptors::from_slots(std::array::from_fn(|slot| {
            [0x20 + slot as u8; 32]
        }))
        .unwrap();
        let mut invalid_predecessor = predecessor.clone();
        invalid_predecessor.slots[2][0] = Fp2::ONE;
        assert!(C6LiveWrapperSources::scaled(
            [0xA1; 32],
            [0xA2; 32],
            cache_layout,
            cache_descriptors.clone(),
            invalid_predecessor,
            successor.clone(),
            2,
            3,
            &weights,
            &embed,
            fixture.manifest(),
            fixture.leaf_witness(),
            fixture.closure_witness(),
            fixture.auxiliary_witness(),
            &specs,
        )
        .is_err());
        let sources = C6LiveWrapperSources::scaled(
            [0xA1; 32],
            [0xA2; 32],
            cache_layout,
            cache_descriptors.clone(),
            predecessor,
            successor,
            2,
            3,
            &weights,
            &embed,
            fixture.manifest(),
            fixture.leaf_witness(),
            fixture.closure_witness(),
            fixture.auxiliary_witness(),
            &specs,
        )
        .unwrap();
        let seed = C6LiveWrapperMaskSeed::from_attempt_secret([0xB1; 32]).unwrap();
        let seed_commitment = seed.commitment();
        let materialized = materialize_live_wrapper_cohorts(sources, &seed, specs).unwrap();

        assert_eq!(materialized.cohorts.len(), 6);
        assert!(materialized.paired_source_digest != [0; 32]);
        assert!(materialized.residual_view_digest != [0; 32]);

        let leaf_payload_len = checked_pow2(specs[2].payload_log2).unwrap();
        let expected_leaf_slots = fixture
            .reference()
            .leaf_tables()
            .iter()
            .enumerate()
            .map(|(slot, witness)| C6WrapperSlotWitness::Witness {
                witness: witness.clone(),
                zk_mask: wrapper_mask_table(
                    &seed,
                    specs[2].cohort_id,
                    slot as u16,
                    leaf_payload_len,
                ),
            })
            .collect();
        let expected_leaf =
            commit_c6_wrapper_cohort([0xA1; 32], specs[2], expected_leaf_slots).unwrap();
        assert_eq!(materialized.cohorts[2].commitment().root, expected_leaf.commitment().root);

        let semantic_len = checked_pow2(fixture.manifest().auxiliary_log2()).unwrap();
        let mut expected_auxiliary_slots = fixture
            .reference()
            .auxiliary_tables()
            .iter()
            .enumerate()
            .map(|(slot, lower)| {
                let mut evaluations = lower.clone();
                evaluations.extend(wrapper_mask_table(
                    &seed,
                    specs[5].cohort_id,
                    slot as u16,
                    semantic_len,
                ));
                C6WrapperSlotWitness::Auxiliary { evaluations }
            })
            .collect::<Vec<_>>();
        expected_auxiliary_slots.extend((16..32).map(|_| C6WrapperSlotWitness::Auxiliary {
            evaluations: vec![Fp2::ZERO; checked_pow2(specs[5].payload_log2).unwrap()],
        }));
        let expected_auxiliary =
            commit_c6_wrapper_cohort([0xA1; 32], specs[5], expected_auxiliary_slots).unwrap();
        assert_eq!(materialized.cohorts[5].commitment().root, expected_auxiliary.commitment().root);

        let commitments = materialized
            .cohorts
            .iter()
            .map(|cohort| cohort.commitment().clone())
            .collect::<Vec<_>>();
        assert!(commitments.iter().map(|commitment| commitment.spec).eq(specs));
        let mut transcript = Transcript::new([0xC1; 32]);
        let fixed = fix_test_c6_wrapper_commitments(
            materialized.statement_digest,
            &commitments,
            &mut transcript,
        )
        .unwrap();
        let binding = live_source_binding_digest(
            materialized.statement_digest,
            materialized.cache_binding_digest,
            materialized.old_len,
            materialized.new_len,
            materialized.residual_manifest_digest,
            materialized.residual_view_digest,
            materialized.paired_source_digest,
            materialized.hidden_witness_digests,
            seed_commitment,
            fixed.binding_digest(),
        );
        assert!(binding != [0; 32]);
        assert_eq!(transcript.bytes_for("c6_wrapper_initial_roots"), 6 * 32);
    }
}

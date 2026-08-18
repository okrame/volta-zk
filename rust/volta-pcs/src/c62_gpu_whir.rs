//! Exact GPU-native oracle boundary for the active C6.2 claimless WHIR fork.
//!
//! This module changes storage and execution only.  The commitment type,
//! BLAKE3 leaf/node serialization, pruned multiproof order and verifier remain
//! the pinned C6.2 Plonky3 types.  It deliberately contains no X4 frame,
//! transcript or proof codec.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleTreeError, PrunedMerklePaths};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use p3_symmetric::MerkleCap;
use p3_whir_c61::pcs::zk::ZkWhirOracleCommitter;
use volta_accel::{
    AccelError, Backend, BackendKind, DeviceBuffer, DeviceMerkleTree, DeviceSlice, Fp2Repr,
};
use volta_field::Fp2;

use crate::c61_whir_reference::{
    C61P3Fp2, c61_p3_fp2_from_volta, c61_reference_mmcs, c61_volta_fp2_from_p3,
};

pub const C62_GPU_WHIR_EXECUTOR_PROFILE: &str = "C62GW1-bounded-binary-frontier";
pub const C62_GPU_WHIR_EXECUTOR_VERSION: u16 = 1;
pub const C62_GPU_WHIR_DEFAULT_TILE_LOG: usize = 20;
pub const C62_GPU_WHIR_STAGING_ELEMENTS: usize = 1 << 20;
pub const C62_GPU_WHIR_FIELD_TAG: [u8; 8] = *b"GL64C621";

pub type C62GpuCommitment = MerkleCap<Goldilocks, [u8; 32]>;
pub type C62GpuMultiProof = PrunedMerklePaths<u8, 32>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C62GpuWhirError(String);

impl C62GpuWhirError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C62GpuWhirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C62GpuWhirError {}

impl From<AccelError> for C62GpuWhirError {
    fn from(error: AccelError) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C62GpuResourceGuard {
    pub logical_codeword_bytes: u64,
    pub tile_workspace_bytes: u64,
    pub fixed_cache_bytes: u64,
    pub other_live_bytes: u64,
    pub reserve_bytes: u64,
    pub available_device_bytes: u64,
}

impl C62GpuResourceGuard {
    pub fn for_lane(
        num_variables: usize,
        folding: usize,
        height: usize,
        tile_log: usize,
        provider_cache: bool,
        available_device_bytes: u64,
    ) -> Result<Self, C62GpuWhirError> {
        if !(1..usize::BITS as usize).contains(&num_variables)
            || folding == 0
            || folding >= num_variables
            || !(10..=22).contains(&tile_log)
            || height < 2
            || !height.is_power_of_two()
        {
            return Err(C62GpuWhirError::new("invalid C62GW1 lane geometry"));
        }
        let elements = 1u64
            .checked_shl(num_variables as u32)
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 lane dimension overflows"))?;
        let width = 1u64
            .checked_shl(folding as u32)
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 lane width overflows"))?;
        let logical_codeword_bytes = width
            .checked_mul(height as u64)
            .and_then(|value| value.checked_mul(8))
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 codeword bytes overflow"))?;
        let tile_leaves = 1u64 << tile_log.min(height.ilog2() as usize);
        let tile_workspace_bytes = width
            .checked_mul(tile_leaves)
            .and_then(|value| value.checked_mul(8))
            .and_then(|value| {
                tile_leaves
                    .checked_mul(2)
                    .and_then(|hashes| hashes.checked_sub(1))
                    .and_then(|hashes| hashes.checked_mul(32))
                    .and_then(|tree| value.checked_add(tree))
            })
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 tile bytes overflow"))?;
        let fixed_cache_bytes = if provider_cache { logical_codeword_bytes } else { 0 };
        // One base upload plus resident Fp2 evaluation/weight factors and one
        // same-size cached-mask/combination scratch. These peaks are summed
        // conservatively although commit and sumcheck do not fully overlap.
        let other_live_bytes = elements
            .checked_mul(8 + 16 + 16)
            .and_then(|value| value.checked_add(logical_codeword_bytes))
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 live-state bytes overflow"))?;
        let reserve_bytes = 4u64 << 30;
        let guard = Self {
            logical_codeword_bytes,
            tile_workspace_bytes,
            fixed_cache_bytes,
            other_live_bytes,
            reserve_bytes,
            available_device_bytes,
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn checked_peak_bytes(self) -> Result<u64, C62GpuWhirError> {
        self.logical_codeword_bytes
            .checked_add(self.tile_workspace_bytes)
            .and_then(|value| value.checked_add(self.fixed_cache_bytes))
            .and_then(|value| value.checked_add(self.other_live_bytes))
            .and_then(|value| value.checked_add(self.reserve_bytes))
            .ok_or_else(|| C62GpuWhirError::new("C62GW1 resource sum overflows"))
    }

    pub fn validate(self) -> Result<(), C62GpuWhirError> {
        if self.logical_codeword_bytes == 0
            || self.tile_workspace_bytes == 0
            || self.reserve_bytes == 0
            || self.available_device_bytes == 0
            || self.checked_peak_bytes()? > self.available_device_bytes
        {
            return Err(C62GpuWhirError::new(
                "C62GW1 device resource guard rejects the requested geometry",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C62ProviderCacheKey {
    pub model_digest: [u8; 32],
    pub protocol_digest: [u8; 32],
    pub parameter_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub field_tag: [u8; 8],
    pub encoder_version: u16,
    pub num_variables: u8,
    pub folding: u8,
    pub height: u64,
}

impl C62ProviderCacheKey {
    pub fn validate(&self) -> Result<(), C62GpuWhirError> {
        if self.model_digest == [0; 32]
            || self.protocol_digest == [0; 32]
            || self.parameter_digest == [0; 32]
            || self.content_digest == [0; 32]
            || self.field_tag != C62_GPU_WHIR_FIELD_TAG
            || self.encoder_version != C62_GPU_WHIR_EXECUTOR_VERSION
            || self.num_variables == 0
            || self.folding == 0
            || self.height < 2
            || !self.height.is_power_of_two()
        {
            return Err(C62GpuWhirError::new("invalid C62GW1 provider-cache key"));
        }
        Ok(())
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"volta.c62.gpu-whir.provider-cache.v1");
        hasher.update(&self.model_digest);
        hasher.update(&self.protocol_digest);
        hasher.update(&self.parameter_digest);
        hasher.update(&self.content_digest);
        hasher.update(&self.field_tag);
        hasher.update(&self.encoder_version.to_le_bytes());
        hasher.update(&[self.num_variables, self.folding]);
        hasher.update(&self.height.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

pub(crate) fn goldilocks_digest(values: &[Goldilocks]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta.c62.gpu-whir.fixed-base-content.v1");
    for chunk in values.chunks(C62_GPU_WHIR_STAGING_ELEMENTS) {
        for value in chunk {
            hasher.update(&value.as_canonical_u64().to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

enum ResidentCodeword {
    Base(DeviceBuffer<u64>),
    Extension(DeviceBuffer<Fp2Repr>),
}

impl ResidentCodeword {
    fn len(&self) -> usize {
        match self {
            Self::Base(buffer) => buffer.len(),
            Self::Extension(buffer) => buffer.len(),
        }
    }

    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        match self {
            Self::Base(buffer) => backend.free_device(buffer),
            Self::Extension(buffer) => backend.free_device(buffer),
        }
    }
}

struct ResidentOracle {
    codeword: ResidentCodeword,
    base_width: usize,
    storage_rows: usize,
    height: usize,
    tile_log: usize,
    /// Level zero contains the roots of the independently rebuilt lower
    /// tiles; later levels are the exact binary BLAKE3 upper tree.
    upper_levels: Vec<Vec<[u8; 32]>>,
}

pub struct C62GpuProverData<M> {
    backend: Arc<Mutex<Backend>>,
    oracle: Option<ResidentOracle>,
    marker: PhantomData<fn() -> M>,
}

impl<M> Drop for C62GpuProverData<M> {
    fn drop(&mut self) {
        let Some(oracle) = self.oracle.take() else { return };
        if let Ok(mut backend) = self.backend.lock() {
            let _ = oracle.codeword.free(&mut backend);
        }
    }
}

struct FixedBaseOwner {
    backend: Arc<Mutex<Backend>>,
    codeword: Option<DeviceBuffer<u64>>,
}

impl Drop for FixedBaseOwner {
    fn drop(&mut self) {
        let Some(codeword) = self.codeword.take() else { return };
        if let Ok(mut backend) = self.backend.lock() {
            let _ = backend.free_device(codeword);
        }
    }
}

/// Provider-local fixed encoding.  It contains no randomness, root,
/// transcript state, PCG material or query-dependent data.
pub struct C62ProviderFixedBase {
    key: C62ProviderCacheKey,
    message_len: usize,
    width: usize,
    owner: FixedBaseOwner,
}

impl C62ProviderFixedBase {
    pub fn key(&self) -> &C62ProviderCacheKey {
        &self.key
    }

    pub fn bytes(&self) -> u64 {
        (self.owner.codeword.as_ref().map_or(0, DeviceBuffer::len) * 8) as u64
    }
}

#[derive(Clone)]
pub struct C62GpuMmcs {
    backend: Arc<Mutex<Backend>>,
    verifier: crate::c61_whir_reference::C61Mmcs,
    tile_log: usize,
    guard: C62GpuResourceGuard,
}

impl C62GpuMmcs {
    pub fn new(
        backend: Backend,
        tile_log: usize,
        guard: C62GpuResourceGuard,
    ) -> Result<Self, C62GpuWhirError> {
        guard.validate()?;
        if backend.kind() != BackendKind::CudaResident {
            return Err(C62GpuWhirError::new("C62GW1 requires the CUDA-resident backend"));
        }
        if !(10..=22).contains(&tile_log) {
            return Err(C62GpuWhirError::new("C62GW1 tile log must lie in 10..=22"));
        }
        Ok(Self {
            backend: Arc::new(Mutex::new(backend)),
            verifier: c61_reference_mmcs(),
            tile_log,
            guard,
        })
    }

    pub fn backend(&self) -> Arc<Mutex<Backend>> {
        Arc::clone(&self.backend)
    }

    pub fn prepare_fixed_base(
        &self,
        key: C62ProviderCacheKey,
        message: &[Goldilocks],
    ) -> Result<Arc<C62ProviderFixedBase>, C62GpuWhirError> {
        key.validate()?;
        if message.len() != 1usize << key.num_variables
            || key.folding as usize >= usize::BITS as usize
            || goldilocks_digest(message) != key.content_digest
        {
            return Err(C62GpuWhirError::new("C62GW1 fixed-base content/key mismatch"));
        }
        let width = 1usize << key.folding;
        let codeword = self.encode_base(message, &[], key.folding as usize, key.height as usize)?;
        if (codeword.len() as u64).saturating_mul(8) > self.guard.fixed_cache_bytes {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            let _ = backend.free_device(codeword);
            return Err(C62GpuWhirError::new("C62GW1 fixed cache exceeds its admission"));
        }
        Ok(Arc::new(C62ProviderFixedBase {
            key,
            message_len: message.len(),
            width,
            owner: FixedBaseOwner { backend: Arc::clone(&self.backend), codeword: Some(codeword) },
        }))
    }

    fn encode_base(
        &self,
        message: &[Goldilocks],
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> Result<DeviceBuffer<u64>, C62GpuWhirError> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let message_device = upload_goldilocks(&mut backend, message)?;
        let randomness_device = match upload_goldilocks(&mut backend, randomness) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = backend.free_device(message_device);
                return Err(error.into());
            }
        };
        let padded = backend.c62_zk_pad_fp_device(
            &message_device,
            message.len(),
            &randomness_device,
            randomness.len(),
            folding,
            height,
        );
        let padded = match padded {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(randomness_device);
                let _ = backend.free_device(message_device);
                return Err(error.into());
            }
        };
        let width = 1usize << folding;
        let encoded = backend.ntt_fp_batch_device(&padded, 0, width, height);
        let _ = backend.free_device(padded);
        let _ = backend.free_device(randomness_device);
        let _ = backend.free_device(message_device);
        Ok(encoded?)
    }

    fn encode_extension(
        &self,
        message: &[C61P3Fp2],
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, C62GpuWhirError> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let message_device = upload_fp2(&mut backend, message)?;
        let randomness_device = match upload_fp2(&mut backend, randomness) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = backend.free_device(message_device);
                return Err(error.into());
            }
        };
        let padded = backend.c62_zk_pad_fp2_device(
            &message_device,
            message.len(),
            &randomness_device,
            randomness.len(),
            folding,
            height,
        );
        let padded = match padded {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(randomness_device);
                let _ = backend.free_device(message_device);
                return Err(error.into());
            }
        };
        let width = 1usize << folding;
        let encoded = backend.ntt_fp2_batch_device(&padded, 0, width, height);
        let _ = backend.free_device(padded);
        let _ = backend.free_device(randomness_device);
        let _ = backend.free_device(message_device);
        Ok(encoded?)
    }

    fn commit_resident<M>(
        &self,
        codeword: ResidentCodeword,
        base_width: usize,
        storage_rows: usize,
        height: usize,
    ) -> Result<(C62GpuCommitment, C62GpuProverData<M>), C62GpuWhirError> {
        let expected_len = storage_rows.checked_mul(height);
        if height < 2 || !height.is_power_of_two() || expected_len != Some(codeword.len()) {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            let _ = codeword.free(&mut backend);
            return Err(C62GpuWhirError::new("invalid C62GW1 resident codeword geometry"));
        }
        let element_bytes = match &codeword {
            ResidentCodeword::Base(_) => 8,
            ResidentCodeword::Extension(_) => 16,
        };
        if (codeword.len() as u64).saturating_mul(element_bytes) > self.guard.logical_codeword_bytes
        {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            let _ = codeword.free(&mut backend);
            return Err(C62GpuWhirError::new("C62GW1 codeword exceeds its admission"));
        }
        let tile_log = self.tile_log.min(height.ilog2() as usize);
        let upper_levels = {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            match build_upper_frontier(&mut backend, &codeword, storage_rows, height, tile_log) {
                Ok(frontier) => frontier,
                Err(error) => {
                    let _ = codeword.free(&mut backend);
                    return Err(error);
                }
            }
        };
        let Some(root) = upper_levels.last().and_then(|level| level.first()).copied() else {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            let _ = codeword.free(&mut backend);
            return Err(C62GpuWhirError::new("empty C62GW1 upper frontier"));
        };
        Ok((
            C62GpuCommitment::new(vec![root]),
            C62GpuProverData {
                backend: Arc::clone(&self.backend),
                oracle: Some(ResidentOracle {
                    codeword,
                    base_width,
                    storage_rows,
                    height,
                    tile_log,
                    upper_levels,
                }),
                marker: PhantomData,
            },
        ))
    }

    fn commit_initial_fresh(
        &self,
        message: &[Goldilocks],
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> Result<(C62GpuCommitment, C62GpuProverData<DenseMatrix<Goldilocks>>), C62GpuWhirError>
    {
        let width = 1usize << folding;
        let encoded = self.encode_base(message, randomness, folding, height)?;
        self.commit_resident(ResidentCodeword::Base(encoded), width, width, height)
    }

    fn commit_initial_cached(
        &self,
        cache: &C62ProviderFixedBase,
        message: &[Goldilocks],
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> Result<(C62GpuCommitment, C62GpuProverData<DenseMatrix<Goldilocks>>), C62GpuWhirError>
    {
        if cache.message_len != message.len()
            || cache.width != 1usize << folding
            || cache.key.folding as usize != folding
            || cache.key.height as usize != height
            || goldilocks_digest(message) != cache.key.content_digest
        {
            return Err(C62GpuWhirError::new("C62GW1 cache/workload geometry mismatch"));
        }
        let mask = self.encode_base(&[], randomness, folding, height)?;
        let combined = {
            let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
            let fixed = cache
                .owner
                .codeword
                .as_ref()
                .ok_or_else(|| C62GpuWhirError::new("C62GW1 fixed cache was released"))?;
            if !fixed.is_owned_by(&backend) || fixed.len() != mask.len() {
                let _ = backend.free_device(mask);
                return Err(C62GpuWhirError::new("C62GW1 cache ownership mismatch"));
            }
            let fixed_slice = match DeviceSlice::new(fixed, 0, fixed.len()) {
                Ok(slice) => slice,
                Err(error) => {
                    let _ = backend.free_device(mask);
                    return Err(error.into());
                }
            };
            let output = match backend.alloc_device::<u64>(fixed.len()) {
                Ok(buffer) => buffer,
                Err(error) => {
                    let _ = backend.free_device(mask);
                    return Err(error.into());
                }
            };
            if let Err(error) = backend.copy_device_rows(
                fixed_slice,
                fixed.len(),
                &output,
                0,
                fixed.len(),
                1,
                fixed.len(),
            ) {
                let _ = backend.free_device(output);
                let _ = backend.free_device(mask);
                return Err(error.into());
            }
            if let Err(error) = backend.fp_add_inplace_device(&output, 0, &mask, 0, mask.len()) {
                let _ = backend.free_device(output);
                let _ = backend.free_device(mask);
                return Err(error.into());
            }
            if let Err(error) = backend.free_device(mask) {
                let _ = backend.free_device(output);
                return Err(error.into());
            }
            output
        };
        self.commit_resident(ResidentCodeword::Base(combined), cache.width, cache.width, height)
    }

    fn commit_extension_native(
        &self,
        message: &[C61P3Fp2],
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> Result<
        (
            C62GpuCommitment,
            C62GpuProverData<FlatMatrixView<Goldilocks, C61P3Fp2, DenseMatrix<C61P3Fp2>>>,
        ),
        C62GpuWhirError,
    > {
        let width = 1usize << folding;
        let encoded = self.encode_extension(message, randomness, folding, height)?;
        self.commit_resident(ResidentCodeword::Extension(encoded), width * 2, width, height)
    }
}

pub enum C62InitialOracleMode {
    Fresh,
    ProviderCached(Arc<C62ProviderFixedBase>),
}

pub struct C62GpuWhirCommitter {
    mmcs: C62GpuMmcs,
    initial: C62InitialOracleMode,
}

#[doc(hidden)]
pub struct C62GpuSumcheckState {
    backend: Arc<Mutex<Backend>>,
    evals: Option<DeviceBuffer<Fp2Repr>>,
    weights: Option<DeviceBuffer<Fp2Repr>>,
    len: usize,
    sum: C61P3Fp2,
}

impl C62GpuSumcheckState {
    fn initialize(
        backend: Arc<Mutex<Backend>>,
        message: &[Goldilocks],
        claims: &[(Point<C61P3Fp2>, C61P3Fp2)],
        coefficients: &[C61P3Fp2],
        batched_target: C61P3Fp2,
        admitted_live_bytes: u64,
    ) -> Result<Self, C62GpuWhirError> {
        if message.len() < 2
            || !message.len().is_power_of_two()
            || claims.is_empty()
            || claims.len() != coefficients.len()
            || claims.iter().any(|(point, _)| {
                1usize.checked_shl(point.num_variables() as u32) != Some(message.len())
            })
        {
            return Err(C62GpuWhirError::new("C62GW1 sumcheck initialization mismatch"));
        }
        if (message.len() as u64).saturating_mul(40) > admitted_live_bytes {
            return Err(C62GpuWhirError::new("C62GW1 sumcheck exceeds its admission"));
        }
        let mut cuda = backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let base = upload_goldilocks(&mut cuda, message)?;
        let evals = match cuda.alloc_device::<Fp2Repr>(message.len()) {
            Ok(value) => value,
            Err(error) => {
                let _ = cuda.free_device(base);
                return Err(error.into());
            }
        };
        if let Err(error) = cuda.fp_to_fp2_device(&base, 0, &evals, 0, message.len()) {
            let _ = cuda.free_device(evals);
            let _ = cuda.free_device(base);
            return Err(error.into());
        }
        cuda.free_device(base)?;
        let weights = match cuda.alloc_device::<Fp2Repr>(message.len()) {
            Ok(value) => value,
            Err(error) => {
                let _ = cuda.free_device(evals);
                return Err(error.into());
            }
        };
        for (index, ((point, _), coefficient)) in claims.iter().zip(coefficients).enumerate() {
            let point = point.iter().copied().map(c61_volta_fp2_from_p3).collect::<Vec<_>>();
            let result = cuda.fp2_affine_eq_weights_inplace_device(
                &weights,
                if index == 0 { 0 } else { message.len() },
                &point,
                c61_volta_fp2_from_p3(*coefficient),
                if index == 0 { Fp2::ZERO } else { Fp2::ONE },
            );
            if let Err(error) = result {
                let _ = cuda.free_device(weights);
                let _ = cuda.free_device(evals);
                return Err(error.into());
            }
        }
        let actual = match (|| {
            cuda.fp2_dot_device(
                DeviceSlice::new(&evals, 0, message.len())?,
                DeviceSlice::new(&weights, 0, message.len())?,
            )
        })() {
            Ok(value) => value,
            Err(error) => {
                let _ = cuda.free_device(weights);
                let _ = cuda.free_device(evals);
                return Err(error.into());
            }
        };
        if c61_p3_fp2_from_volta(actual) != batched_target {
            let _ = cuda.free_device(weights);
            let _ = cuda.free_device(evals);
            return Err(C62GpuWhirError::new("C62GW1 resident initial sumcheck claim mismatch"));
        }
        drop(cuda);
        Ok(Self {
            backend,
            evals: Some(evals),
            weights: Some(weights),
            len: message.len(),
            sum: batched_target,
        })
    }

    fn download_poly(
        &self,
        buffer: &DeviceBuffer<Fp2Repr>,
    ) -> Result<Poly<C61P3Fp2>, C62GpuWhirError> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let values = backend.download_device(buffer, 0, self.len)?;
        Ok(Poly::new(values.into_iter().map(Fp2::from).map(c61_p3_fp2_from_volta).collect()))
    }
}

impl Drop for C62GpuSumcheckState {
    fn drop(&mut self) {
        if let Ok(mut backend) = self.backend.lock() {
            if let Some(evals) = self.evals.take() {
                let _ = backend.free_device(evals);
            }
            if let Some(weights) = self.weights.take() {
                let _ = backend.free_device(weights);
            }
        }
    }
}

impl ResidualSumcheckProver<Goldilocks, C61P3Fp2> for C62GpuSumcheckState {
    type Error = C62GpuWhirError;

    fn claimed_sum(&self) -> C61P3Fp2 {
        self.sum
    }

    fn num_variables(&self) -> usize {
        self.len.ilog2() as usize
    }

    fn evals(&self) -> Result<Poly<C61P3Fp2>, Self::Error> {
        self.download_poly(self.evals.as_ref().expect("resident evals are live"))
    }

    fn eval(&self, point: &Point<C61P3Fp2>) -> Result<C61P3Fp2, Self::Error> {
        if 1usize.checked_shl(point.num_variables() as u32) != Some(self.len) {
            return Err(C62GpuWhirError::new("C62GW1 resident MLE point mismatch"));
        }
        let point = point.iter().copied().map(c61_volta_fp2_from_p3).collect::<Vec<_>>();
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let value = backend.mle_eval_device(
            DeviceSlice::new(self.evals.as_ref().expect("resident evals are live"), 0, self.len)?,
            &point,
        )?;
        Ok(c61_p3_fp2_from_volta(value))
    }

    fn round_coefficients(&self) -> Result<(C61P3Fp2, C61P3Fp2), Self::Error> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let [c0, c2] = backend.fp2_product_round_prefix_device(
            DeviceSlice::new(self.evals.as_ref().expect("resident evals are live"), 0, self.len)?,
            DeviceSlice::new(
                self.weights.as_ref().expect("resident weights are live"),
                0,
                self.len,
            )?,
        )?;
        Ok((c61_p3_fp2_from_volta(c0), c61_p3_fp2_from_volta(c2)))
    }

    fn fold_round_with_coefficients(
        &mut self,
        c0: C61P3Fp2,
        c_inf: C61P3Fp2,
        gamma: C61P3Fp2,
    ) -> Result<(), Self::Error> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let old_evals = self.evals.take().expect("resident evals are live");
        let old_weights = self.weights.take().expect("resident weights are live");
        let r = c61_volta_fp2_from_p3(gamma);
        let next_evals = match backend.fp2_fold_prefix_device(&old_evals, 0, self.len, r) {
            Ok(value) => value,
            Err(error) => {
                self.evals = Some(old_evals);
                self.weights = Some(old_weights);
                return Err(error.into());
            }
        };
        let next_weights = match backend.fp2_fold_prefix_device(&old_weights, 0, self.len, r) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(next_evals);
                self.evals = Some(old_evals);
                self.weights = Some(old_weights);
                return Err(error.into());
            }
        };
        let evals_free = backend.free_device(old_evals);
        let weights_free = backend.free_device(old_weights);
        if let Err(error) = evals_free.and(weights_free) {
            let _ = backend.free_device(next_evals);
            let _ = backend.free_device(next_weights);
            return Err(error.into());
        }
        self.evals = Some(next_evals);
        self.weights = Some(next_weights);
        self.len /= 2;
        self.sum = c0 * (C61P3Fp2::ONE - gamma)
            + (self.sum - c0) * gamma
            + c_inf * gamma * (gamma - C61P3Fp2::ONE);
        Ok(())
    }

    fn scale_weights_and_claim(&mut self, scale: C61P3Fp2) -> Result<(), Self::Error> {
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        backend.fp2_scale_inplace_device(
            self.weights.as_ref().expect("resident weights are live"),
            0,
            self.len,
            c61_volta_fp2_from_p3(scale),
        )?;
        self.sum *= scale;
        Ok(())
    }

    fn weights(&self) -> Result<Poly<C61P3Fp2>, Self::Error> {
        self.download_poly(self.weights.as_ref().expect("resident weights are live"))
    }

    fn accumulate_claim(
        &mut self,
        weights_delta: &[C61P3Fp2],
        sum_delta: C61P3Fp2,
    ) -> Result<(), Self::Error> {
        if weights_delta.len() != self.len {
            return Err(C62GpuWhirError::new("C62GW1 resident weight-delta mismatch"));
        }
        let mut backend = self.backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
        let delta = upload_fp2(&mut backend, weights_delta)?;
        let result = backend.fp2_add_inplace_device(
            self.weights.as_ref().expect("resident weights are live"),
            0,
            &delta,
            0,
            self.len,
        );
        let free = backend.free_device(delta);
        result?;
        free?;
        self.sum += sum_delta;
        Ok(())
    }
}

impl C62GpuWhirCommitter {
    pub fn fresh(mmcs: C62GpuMmcs) -> Self {
        Self { mmcs, initial: C62InitialOracleMode::Fresh }
    }

    pub fn provider_cached(mmcs: C62GpuMmcs, cache: Arc<C62ProviderFixedBase>) -> Self {
        Self { mmcs, initial: C62InitialOracleMode::ProviderCached(cache) }
    }
}

impl ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs> for C62GpuWhirCommitter {
    type Error = C62GpuWhirError;
    type SumcheckState = C62GpuSumcheckState;

    fn initialize_sumcheck(
        &self,
        message: &[Goldilocks],
        claims: &[(Point<C61P3Fp2>, C61P3Fp2)],
        coefficients: &[C61P3Fp2],
        batched_target: C61P3Fp2,
    ) -> Result<Self::SumcheckState, Self::Error> {
        C62GpuSumcheckState::initialize(
            self.mmcs.backend(),
            message,
            claims,
            coefficients,
            batched_target,
            self.mmcs.guard.other_live_bytes,
        )
    }

    fn commit_initial(
        &self,
        message: &[Goldilocks],
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> Result<(C62GpuCommitment, C62GpuProverData<DenseMatrix<Goldilocks>>), Self::Error> {
        match &self.initial {
            C62InitialOracleMode::Fresh => {
                self.mmcs.commit_initial_fresh(message, randomness, folding, height)
            }
            C62InitialOracleMode::ProviderCached(cache) => {
                self.mmcs.commit_initial_cached(cache, message, randomness, folding, height)
            }
        }
    }

    fn commit_extension(
        &self,
        message: &[C61P3Fp2],
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> Result<
        (
            C62GpuCommitment,
            C62GpuProverData<FlatMatrixView<Goldilocks, C61P3Fp2, DenseMatrix<C61P3Fp2>>>,
        ),
        Self::Error,
    > {
        self.mmcs.commit_extension_native(message, randomness, folding, height)
    }
}

impl Mmcs<Goldilocks> for C62GpuMmcs {
    type ProverData<M> = C62GpuProverData<M>;
    type Commitment = C62GpuCommitment;
    type Proof = Vec<[u8; 32]>;
    type MultiProof = C62GpuMultiProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        assert_eq!(inputs.len(), 1, "C62GW1 admits one WHIR matrix per root");
        let matrix = inputs.into_iter().next().unwrap();
        let width = matrix.width();
        let height = matrix.height();
        assert!(height >= 2 && height.is_power_of_two() && width > 0);
        let codeword = {
            let mut backend = self.backend.lock().expect("C62GW1 CUDA lock poisoned");
            upload_transposed_matrix(&mut backend, &matrix)
                .unwrap_or_else(|error| panic!("C62GW1 encoded-matrix upload failed: {error}"))
        };
        self.commit_resident(ResidentCodeword::Base(codeword), width, width, height)
            .unwrap_or_else(|error| panic!("C62GW1 encoded-matrix commit failed: {error}"))
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
        let (mut rows, proof) = self.open_multi_batch(&[index], prover_data);
        BatchOpening::new(rows.swap_remove(0), proof.sibling_hashes)
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
        &self,
        _prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        panic!("C62GW1 deliberately exposes no host-resident oracle matrix")
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        self.verifier.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }

    fn open_multi_batch<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let oracle = prover_data.oracle.as_ref().expect("C62GW1 prover data was released");
        open_resident_oracle(&prover_data.backend, oracle, indices)
            .unwrap_or_else(|error| panic!("C62GW1 resident opening failed: {error}"))
    }

    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.verifier.verify_multi_batch(commitment, dimensions, indices, opened_values, proof)
    }
}

fn upload_goldilocks(
    backend: &mut Backend,
    values: &[Goldilocks],
) -> Result<DeviceBuffer<u64>, AccelError> {
    let logical_len = values.len();
    let buffer = backend.alloc_device::<u64>(logical_len.max(1))?;
    if values.is_empty() {
        if let Err(error) = backend.upload_device(&buffer, 0, &[0]) {
            let _ = backend.free_device(buffer);
            return Err(error);
        }
        return Ok(buffer);
    }
    for (chunk_index, chunk) in values.chunks(C62_GPU_WHIR_STAGING_ELEMENTS).enumerate() {
        let staging = chunk.iter().map(PrimeField64::as_canonical_u64).collect::<Vec<_>>();
        if let Err(error) =
            backend.upload_device(&buffer, chunk_index * C62_GPU_WHIR_STAGING_ELEMENTS, &staging)
        {
            let _ = backend.free_device(buffer);
            return Err(error);
        }
    }
    Ok(buffer)
}

fn fp2_repr(value: &C61P3Fp2) -> Fp2Repr {
    let coefficients: &[Goldilocks] = value.as_basis_coefficients_slice();
    Fp2Repr { c0: coefficients[0].as_canonical_u64(), c1: coefficients[1].as_canonical_u64() }
}

fn upload_fp2(
    backend: &mut Backend,
    values: &[C61P3Fp2],
) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
    let logical_len = values.len();
    let buffer = backend.alloc_device::<Fp2Repr>(logical_len.max(1))?;
    if values.is_empty() {
        if let Err(error) = backend.upload_device(&buffer, 0, &[Fp2Repr::default()]) {
            let _ = backend.free_device(buffer);
            return Err(error);
        }
        return Ok(buffer);
    }
    for (chunk_index, chunk) in values.chunks(C62_GPU_WHIR_STAGING_ELEMENTS).enumerate() {
        let staging = chunk.iter().map(fp2_repr).collect::<Vec<_>>();
        if let Err(error) =
            backend.upload_device(&buffer, chunk_index * C62_GPU_WHIR_STAGING_ELEMENTS, &staging)
        {
            let _ = backend.free_device(buffer);
            return Err(error);
        }
    }
    Ok(buffer)
}

fn upload_transposed_matrix<M: Matrix<Goldilocks>>(
    backend: &mut Backend,
    matrix: &M,
) -> Result<DeviceBuffer<u64>, AccelError> {
    let width = matrix.width();
    let height = matrix.height();
    let len = width
        .checked_mul(height)
        .ok_or(AccelError::InvalidInput("matrix upload geometry overflows"))?;
    let output = backend.alloc_device::<u64>(len)?;
    for column in 0..width {
        for start in (0..height).step_by(C62_GPU_WHIR_STAGING_ELEMENTS) {
            let end = (start + C62_GPU_WHIR_STAGING_ELEMENTS).min(height);
            let staging = (start..end)
                .map(|row| unsafe { matrix.get_unchecked(row, column) }.as_canonical_u64())
                .collect::<Vec<_>>();
            if let Err(error) = backend.upload_device(&output, column * height + start, &staging) {
                let _ = backend.free_device(output);
                return Err(error);
            }
        }
    }
    Ok(output)
}

enum TileCodeword {
    Base(DeviceBuffer<u64>),
    Extension(DeviceBuffer<Fp2Repr>),
}

impl TileCodeword {
    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        match self {
            Self::Base(buffer) => backend.free_device(buffer),
            Self::Extension(buffer) => backend.free_device(buffer),
        }
    }
}

fn build_tile(
    backend: &mut Backend,
    codeword: &ResidentCodeword,
    storage_rows: usize,
    height: usize,
    start: usize,
    tile_len: usize,
) -> Result<(TileCodeword, DeviceMerkleTree), C62GpuWhirError> {
    match codeword {
        ResidentCodeword::Base(source) => {
            let source_slice = DeviceSlice::new(source, start, source.len() - start)?;
            let tile_elements = storage_rows
                .checked_mul(tile_len)
                .ok_or_else(|| C62GpuWhirError::new("C62GW1 base tile geometry overflows"))?;
            let tile = backend.alloc_device::<u64>(tile_elements)?;
            if let Err(error) = backend.copy_device_rows(
                source_slice,
                height,
                &tile,
                0,
                tile_len,
                storage_rows,
                tile_len,
            ) {
                let _ = backend.free_device(tile);
                return Err(error.into());
            }
            match backend.hash_fp_tree_device(&tile, storage_rows, tile_len) {
                Ok(tree) => Ok((TileCodeword::Base(tile), tree)),
                Err(error) => {
                    let _ = backend.free_device(tile);
                    Err(error.into())
                }
            }
        }
        ResidentCodeword::Extension(source) => {
            let source_slice = DeviceSlice::new(source, start, source.len() - start)?;
            let tile_elements = storage_rows
                .checked_mul(tile_len)
                .ok_or_else(|| C62GpuWhirError::new("C62GW1 extension tile geometry overflows"))?;
            let tile = backend.alloc_device::<Fp2Repr>(tile_elements)?;
            if let Err(error) = backend.copy_device_rows(
                source_slice,
                height,
                &tile,
                0,
                tile_len,
                storage_rows,
                tile_len,
            ) {
                let _ = backend.free_device(tile);
                return Err(error.into());
            }
            match backend.hash_fp2_tree_device(&tile, storage_rows, tile_len) {
                Ok(tree) => Ok((TileCodeword::Extension(tile), tree)),
                Err(error) => {
                    let _ = backend.free_device(tile);
                    Err(error.into())
                }
            }
        }
    }
}

fn build_upper_frontier(
    backend: &mut Backend,
    codeword: &ResidentCodeword,
    storage_rows: usize,
    height: usize,
    tile_log: usize,
) -> Result<Vec<Vec<[u8; 32]>>, C62GpuWhirError> {
    let tile_len = 1usize << tile_log;
    let mut tile_roots = Vec::with_capacity(height / tile_len);
    for start in (0..height).step_by(tile_len) {
        let (tile, tree) = build_tile(backend, codeword, storage_rows, height, start, tile_len)?;
        let root_result = backend.merkle_root_device(&tree);
        let tree_free = backend.free_device_merkle_tree(tree);
        let tile_free = tile.free(backend);
        let root = root_result?;
        tree_free?;
        tile_free?;
        tile_roots.push(root);
    }
    let mut levels = vec![tile_roots];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
        levels.push(next);
    }
    Ok(levels)
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    *blake3::hash(&bytes).as_bytes()
}

fn gather_rows(
    backend: &mut Backend,
    oracle: &ResidentOracle,
    indices: &[u32],
) -> Result<Vec<Vec<Goldilocks>>, C62GpuWhirError> {
    let device_indices = backend.upload_new_device(indices)?;
    let result: Result<Vec<Vec<Goldilocks>>, C62GpuWhirError> = (|| match &oracle.codeword {
        ResidentCodeword::Base(codeword) => {
            let gathered = backend.pcs_gather_fp_device(
                codeword,
                oracle.storage_rows,
                oracle.height,
                &device_indices,
                indices.len(),
            )?;
            let raw = backend.download_device(&gathered, 0, oracle.base_width * indices.len());
            let free = backend.free_device(gathered);
            let raw = raw?;
            free?;
            Ok(raw
                .chunks_exact(oracle.base_width)
                .map(|row| row.iter().copied().map(Goldilocks::new).collect())
                .collect())
        }
        ResidentCodeword::Extension(codeword) => {
            let gathered = backend.pcs_gather_fp2_device(
                codeword,
                oracle.storage_rows,
                oracle.height,
                &device_indices,
                indices.len(),
            )?;
            let raw = backend.download_device(&gathered, 0, oracle.storage_rows * indices.len());
            let free = backend.free_device(gathered);
            let raw = raw?;
            free?;
            Ok(raw
                .chunks_exact(oracle.storage_rows)
                .map(|row| {
                    row.iter()
                        .flat_map(|value| [Goldilocks::new(value.c0), Goldilocks::new(value.c1)])
                        .collect()
                })
                .collect())
        }
    })();
    let free = backend.free_device(device_indices);
    match (result, free) {
        (Ok(rows), Ok(())) => Ok(rows),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn open_resident_oracle(
    backend: &Arc<Mutex<Backend>>,
    oracle: &ResidentOracle,
    indices: &[usize],
) -> Result<(Vec<Vec<Vec<Goldilocks>>>, C62GpuMultiProof), C62GpuWhirError> {
    if indices.is_empty() || indices.iter().any(|&index| index >= oracle.height) {
        return Err(C62GpuWhirError::new("C62GW1 opening index is empty or out of bounds"));
    }
    let mut unique = indices.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let unique_u32 = unique
        .iter()
        .map(|&index| u32::try_from(index).map_err(|_| C62GpuWhirError::new("index exceeds u32")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut backend = backend.lock().map_err(|_| C62GpuWhirError::new("CUDA lock"))?;
    let unique_rows = gather_rows(&mut backend, oracle, &unique_u32)?;
    let row_by_index = unique.iter().copied().zip(unique_rows).collect::<BTreeMap<_, _>>();

    let tile_len = 1usize << oracle.tile_log;
    let mut by_tile = BTreeMap::<usize, Vec<usize>>::new();
    for &index in &unique {
        by_tile.entry(index / tile_len).or_default().push(index);
    }
    let mut lower_siblings = BTreeMap::<(usize, usize), [u8; 32]>::new();
    for (tile_index, global_indices) in by_tile {
        let tile_start = tile_index * tile_len;
        let local =
            global_indices.iter().map(|index| (index - tile_start) as u32).collect::<Vec<_>>();
        let (tile, tree) = build_tile(
            &mut backend,
            &oracle.codeword,
            oracle.storage_rows,
            oracle.height,
            tile_start,
            tile_len,
        )?;
        let device_indices = match backend.upload_new_device(&local) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = backend.free_device_merkle_tree(tree);
                let _ = tile.free(&mut backend);
                return Err(error.into());
            }
        };
        let paths = match backend.merkle_paths_device(&tree, &device_indices, local.len()) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = backend.free_device(device_indices);
                let _ = backend.free_device_merkle_tree(tree);
                let _ = tile.free(&mut backend);
                return Err(error.into());
            }
        };
        let path_bytes = backend.download_device(&paths, 0, local.len() * oracle.tile_log * 32);
        let paths_free = backend.free_device(paths);
        let indices_free = backend.free_device(device_indices);
        let tree_free = backend.free_device_merkle_tree(tree);
        let tile_free = tile.free(&mut backend);
        let path_bytes = path_bytes?;
        paths_free?;
        indices_free?;
        tree_free?;
        tile_free?;
        for (query, &global) in global_indices.iter().enumerate() {
            for level in 0..oracle.tile_log {
                let offset = (query * oracle.tile_log + level) * 32;
                let digest: [u8; 32] = path_bytes[offset..offset + 32].try_into().unwrap();
                lower_siblings.insert((level, (global >> level) ^ 1), digest);
            }
        }
    }

    let mut nodes = unique.clone();
    let mut siblings = Vec::new();
    let total_levels = oracle.height.ilog2() as usize;
    for level in 0..total_levels {
        let mut parents = Vec::with_capacity(nodes.len());
        let mut cursor = 0;
        while cursor < nodes.len() {
            let group = nodes[cursor] / 2;
            let group_start = group * 2;
            let mut member = cursor;
            for child in 0..2 {
                let child_index = group_start + child;
                if member < nodes.len() && nodes[member] == child_index {
                    member += 1;
                } else {
                    let digest = if level < oracle.tile_log {
                        *lower_siblings.get(&(level, child_index)).ok_or_else(|| {
                            C62GpuWhirError::new("missing rebuilt lower-frontier digest")
                        })?
                    } else {
                        oracle.upper_levels[level - oracle.tile_log][child_index]
                    };
                    siblings.push(digest);
                }
            }
            parents.push(group);
            cursor = member;
        }
        nodes = parents;
    }
    let rows = indices.iter().map(|index| vec![row_by_index[index].clone()]).collect();
    Ok((rows, C62GpuMultiProof { sibling_hashes: siblings }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_guard_is_fail_closed() {
        let valid = C62GpuResourceGuard {
            logical_codeword_bytes: 4,
            tile_workspace_bytes: 4,
            fixed_cache_bytes: 4,
            other_live_bytes: 4,
            reserve_bytes: 4,
            available_device_bytes: 20,
        };
        assert!(valid.validate().is_ok());
        assert!(C62GpuResourceGuard { available_device_bytes: 19, ..valid }.validate().is_err());
        assert!(C62GpuResourceGuard { reserve_bytes: 0, ..valid }.validate().is_err());

        let d28 = C62GpuResourceGuard::for_lane(28, 8, 1 << 22, 20, true, 80u64 << 30).unwrap();
        assert_eq!(d28.checked_peak_bytes().unwrap(), (40u64 << 30) + (64u64 << 20) - 32);
        assert!(C62GpuResourceGuard::for_lane(28, 8, 1 << 22, 20, true, 40u64 << 30).is_err());
    }

    #[test]
    fn cache_key_binds_every_authorized_dimension() {
        let key = C62ProviderCacheKey {
            model_digest: [1; 32],
            protocol_digest: [2; 32],
            parameter_digest: [3; 32],
            content_digest: [4; 32],
            field_tag: C62_GPU_WHIR_FIELD_TAG,
            encoder_version: C62_GPU_WHIR_EXECUTOR_VERSION,
            num_variables: 14,
            folding: 2,
            height: 1 << 13,
        };
        key.validate().unwrap();
        let digest = key.binding_digest();
        let mut changed = key.clone();
        changed.height *= 2;
        assert_ne!(digest, changed.binding_digest());
        changed = key.clone();
        changed.protocol_digest[0] ^= 1;
        assert_ne!(digest, changed.binding_digest());
        changed = key.clone();
        changed.content_digest[0] ^= 1;
        assert_ne!(digest, changed.binding_digest());
    }

    #[test]
    fn binary_upper_frontier_matches_direct_tree() {
        let leaves = (0u64..16)
            .map(|index| *blake3::hash(&index.to_le_bytes()).as_bytes())
            .collect::<Vec<_>>();
        let mut levels = vec![leaves.clone()];
        while levels.last().unwrap().len() > 1 {
            levels.push(
                levels
                    .last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| hash_pair(pair[0], pair[1]))
                    .collect(),
            );
        }
        let tile_roots = leaves
            .chunks_exact(4)
            .map(|tile| {
                let left = hash_pair(tile[0], tile[1]);
                let right = hash_pair(tile[2], tile[3]);
                hash_pair(left, right)
            })
            .collect::<Vec<_>>();
        let upper = hash_pair(
            hash_pair(tile_roots[0], tile_roots[1]),
            hash_pair(tile_roots[2], tile_roots[3]),
        );
        assert_eq!(upper, levels.last().unwrap()[0]);
    }

    #[cfg(feature = "cuda")]
    fn cuda_mmcs(tile_log: usize) -> Option<C62GpuMmcs> {
        let backend = match Backend::cuda_resident() {
            Ok(backend) => backend,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping C62GW1 CUDA differential: {error}");
                return None;
            }
            Err(error) => panic!("CUDA is required for C62GW1 differential: {error}"),
        };
        C62GpuMmcs::new(
            backend,
            tile_log,
            C62GpuResourceGuard {
                logical_codeword_bytes: 1 << 40,
                tile_workspace_bytes: 1 << 40,
                fixed_cache_bytes: 1 << 40,
                other_live_bytes: 1 << 40,
                reserve_bytes: 1 << 40,
                available_device_bytes: 5 << 40,
            },
        )
        .map(Some)
        .unwrap()
    }

    #[cfg(feature = "cuda")]
    fn padded_base(
        message: &[Goldilocks],
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> DenseMatrix<Goldilocks> {
        let width = 1usize << folding;
        let message_rows = message.len() / width;
        let randomness_rows = randomness.len() / width;
        let mut values = vec![Goldilocks::new(0); width * height];
        for limb in 0..width {
            for row in 0..message_rows {
                values[row * width + limb] = message[limb * message_rows + row];
            }
            for row in 0..randomness_rows {
                values[(message_rows + row) * width + limb] =
                    randomness[limb * randomness_rows + row];
            }
        }
        DenseMatrix::new(values, width)
    }

    #[cfg(feature = "cuda")]
    fn padded_extension(
        message: &[C61P3Fp2],
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> DenseMatrix<C61P3Fp2> {
        let width = 1usize << folding;
        let message_rows = message.len() / width;
        let randomness_rows = randomness.len() / width;
        let zero =
            C61P3Fp2::from_basis_coefficients_slice(&[Goldilocks::new(0), Goldilocks::new(0)])
                .unwrap();
        let mut values = vec![zero; width * height];
        for limb in 0..width {
            for row in 0..message_rows {
                values[row * width + limb] = message[limb * message_rows + row];
            }
            for row in 0..randomness_rows {
                values[(message_rows + row) * width + limb] =
                    randomness[limb * randomness_rows + row];
            }
        }
        DenseMatrix::new(values, width)
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_native_initial_cache_root_rows_and_pruned_proof_are_exact() {
        use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};

        let Some(gpu) = cuda_mmcs(10) else { return };
        let (folding, width, height) = (2usize, 4usize, 1usize << 12);
        let message = (0..1usize << 11)
            .map(|index| Goldilocks::new(index as u64 * 37 + 11))
            .collect::<Vec<_>>();
        let randomness =
            (0..width * 8).map(|index| Goldilocks::new(index as u64 * 53 + 19)).collect::<Vec<_>>();
        let dft = Radix2DFTSmallBatch::<Goldilocks>::new(height);
        let encoded = dft.dft_batch(padded_base(&message, &randomness, folding, height));
        let reference = c61_reference_mmcs();
        let (reference_root, reference_data) = reference.commit_matrix(encoded);

        let (fresh_root, fresh_data) =
            gpu.commit_initial_fresh(&message, &randomness, folding, height).unwrap();
        assert_eq!(fresh_root, reference_root);

        let key = C62ProviderCacheKey {
            model_digest: [1; 32],
            protocol_digest: [2; 32],
            parameter_digest: [3; 32],
            content_digest: goldilocks_digest(&message),
            field_tag: C62_GPU_WHIR_FIELD_TAG,
            encoder_version: C62_GPU_WHIR_EXECUTOR_VERSION,
            num_variables: 11,
            folding: folding as u8,
            height: height as u64,
        };
        let cache = gpu.prepare_fixed_base(key, &message).unwrap();
        let (cached_root, cached_data) =
            gpu.commit_initial_cached(&cache, &message, &randomness, folding, height).unwrap();
        assert_eq!(cached_root, reference_root);

        let indices = [1usize, 1023, 1024, 2049, 4095];
        let (reference_rows, reference_proof) =
            reference.open_multi_batch(&indices, &reference_data);
        let (fresh_rows, fresh_proof) = gpu.open_multi_batch(&indices, &fresh_data);
        let (cached_rows, cached_proof) = gpu.open_multi_batch(&indices, &cached_data);
        assert_eq!(fresh_rows, reference_rows);
        assert_eq!(cached_rows, reference_rows);
        assert_eq!(fresh_proof.sibling_hashes, reference_proof.sibling_hashes);
        assert_eq!(cached_proof.sibling_hashes, reference_proof.sibling_hashes);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_native_extension_root_rows_and_pruned_proof_are_exact() {
        use p3_commit::ExtensionMmcs;
        use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};

        let Some(gpu) = cuda_mmcs(10) else { return };
        let (folding, width, height) = (2usize, 4usize, 1usize << 11);
        let make = |index: usize, a: u64, b: u64| {
            C61P3Fp2::from_basis_coefficients_slice(&[
                Goldilocks::new(index as u64 * a + 7),
                Goldilocks::new(index as u64 * b + 13),
            ])
            .unwrap()
        };
        let message = (0..1usize << 10).map(|index| make(index, 37, 41)).collect::<Vec<_>>();
        let randomness = (0..width * 8).map(|index| make(index, 53, 59)).collect::<Vec<_>>();
        let dft = Radix2DFTSmallBatch::<Goldilocks>::new(height);
        let encoded =
            dft.dft_algebra_batch(padded_extension(&message, &randomness, folding, height));
        let reference = ExtensionMmcs::new(c61_reference_mmcs());
        let (reference_root, reference_data) = reference.commit_matrix(encoded);
        let (gpu_root, gpu_data) =
            gpu.commit_extension_native(&message, &randomness, folding, height).unwrap();
        assert_eq!(gpu_root, reference_root);

        let gpu_extension = ExtensionMmcs::<Goldilocks, C61P3Fp2, _>::new(gpu.clone());
        let indices = [0usize, 511, 1024, 1537, 2047];
        let (reference_rows, reference_proof) =
            reference.open_multi_batch(&indices, &reference_data);
        let (gpu_rows, gpu_proof) = gpu_extension.open_multi_batch(&indices, &gpu_data);
        assert_eq!(gpu_rows, reference_rows);
        assert_eq!(gpu_proof.sibling_hashes, reference_proof.sibling_hashes);
    }
}

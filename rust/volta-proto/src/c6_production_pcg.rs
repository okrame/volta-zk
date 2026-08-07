//! Fail-closed bridge from the durable C6 paired reservation to two real
//! fase-D PCG tapes.

use crate::{
    C6PairedSourceWitness, C6SetupManifest, C6SlotReservation, C6SourceCoordinate,
    C6_BASELINE_RAW_CORRELATIONS, C6_MAC_COORDINATES,
};
use volta_field::{Fp, Fp2, P};
use volta_mac::{ConnectionCorrelationScope, CorrScheduleAudit, CorrelationStream, VerifierCtx};
use volta_pcg::{
    CorrelationAllocation, CorrelationDomain, GgmPrg, ProductionFaseDConnection,
    ResponseAuthorizationStore, VerifierPcgPool,
};

const SOURCE_BINDING_DOMAIN: &str = "volta-zk/c6/production-paired-source/v1";
const REPLAY_MAGIC: &[u8] = b"C6VRP1\0\0";
const REPLAY_VERSION: u16 = 1;
pub const C61_PRODUCTION_SUB_CORRELATIONS: usize = 4_793_614;
pub const C61_PRODUCTION_FULL_CORRELATIONS: usize = 221_039;
pub const C61_VERIFIER_REPLAY_STATE_BYTES: usize = 8
    + 4
    + 7 * 32
    + 2 * 16
    + 8
    + 2 * (C61_PRODUCTION_SUB_CORRELATIONS + C61_PRODUCTION_FULL_CORRELATIONS) * 16
    + 32;

type Result<T> = std::result::Result<T, String>;

/// Live paired allocation. Dropping before [`Self::finish_success`] leaves
/// both underlying connection journals terminally burned by their normal
/// fail-closed drop lifecycle.
pub struct C6ProductionPairedPcgAttempt {
    setup_manifest_digest: [u8; 32],
    reservation: C6SlotReservation,
    reservation_digest: [u8; 32],
    tape_ids: [[u8; 32]; C6_MAC_COORDINATES],
    allocations: [CorrelationAllocation; C6_MAC_COORDINATES],
    prover: [CorrelationStream; C6_MAC_COORDINATES],
    verifier: [VerifierCtx; C6_MAC_COORDINATES],
    verifier_replay_pools: Option<[VerifierPcgPool; C6_MAC_COORDINATES]>,
    verifier_deltas: [volta_field::Fp2; C6_MAC_COORDINATES],
    verifier_scope: ConnectionCorrelationScope,
    connections: [ProductionFaseDConnection; C6_MAC_COORDINATES],
    source_sealed: bool,
    source_allocation_binding_digest: Option<[u8; 32]>,
}

/// Client-only seed for idempotent verification of one exact certificate.
///
/// The contained key pools are never exposed. Fresh contexts may be derived
/// repeatedly only after the owner is bound to a nonzero certificate digest;
/// this supports the required 4T and maxT(N) measurements without allocating
/// a second provider correlation range or regenerating a proof.
pub struct C6ProductionVerifierReplayOwner {
    setup_manifest_digest: [u8; 32],
    reservation_digest: [u8; 32],
    source_allocation_binding_digest: [u8; 32],
    statement_digest: [u8; 32],
    pools: [VerifierPcgPool; C6_MAC_COORDINATES],
    deltas: [volta_field::Fp2; C6_MAC_COORDINATES],
    scope: ConnectionCorrelationScope,
}

pub struct C6BoundProductionVerifierReplay {
    owner: C6ProductionVerifierReplayOwner,
    certificate_digest: [u8; 32],
}

impl C6ProductionVerifierReplayOwner {
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn setup_manifest_digest(&self) -> [u8; 32] {
        self.setup_manifest_digest
    }

    pub fn reservation_digest(&self) -> [u8; 32] {
        self.reservation_digest
    }

    pub fn source_allocation_binding_digest(&self) -> [u8; 32] {
        self.source_allocation_binding_digest
    }

    pub fn bind_certificate(
        self,
        certificate_digest: [u8; 32],
    ) -> Result<C6BoundProductionVerifierReplay> {
        if certificate_digest == [0; 32] {
            return Err("C6 verifier replay cannot bind a zero certificate digest".to_owned());
        }
        Ok(C6BoundProductionVerifierReplay { owner: self, certificate_digest })
    }
}

impl C6BoundProductionVerifierReplay {
    pub fn fresh_contexts(
        &self,
        certificate_digest: [u8; 32],
    ) -> Result<[VerifierCtx; C6_MAC_COORDINATES]> {
        if certificate_digest != self.certificate_digest {
            return Err("C6 verifier replay requested a different certificate".to_owned());
        }
        Ok([
            VerifierCtx::from_pcg_pool_connection(
                self.owner.deltas[0],
                self.owner.pools[0].clone(),
                self.owner.scope,
            ),
            VerifierCtx::from_pcg_pool_connection(
                self.owner.deltas[1],
                self.owner.pools[1].clone(),
                self.owner.scope,
            ),
        ])
    }

    /// Canonical client-private state. These verifier keys are never part of
    /// setup traffic or the provider-to-client certificate.
    pub fn encode_client_state(&self) -> Result<Vec<u8>> {
        encode_bound_replay(self)
    }

    pub fn decode_client_state(bytes: &[u8]) -> Result<Self> {
        decode_bound_replay(
            bytes,
            C61_PRODUCTION_SUB_CORRELATIONS,
            C61_PRODUCTION_FULL_CORRELATIONS,
        )
    }

    pub fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }
}

struct ReplayWriter(Vec<u8>);

impl ReplayWriter {
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn fp2(&mut self, value: Fp2) {
        self.0.extend_from_slice(&value.c0.value().to_le_bytes());
        self.0.extend_from_slice(&value.c1.value().to_le_bytes());
    }
}

struct ReplayReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReplayReader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "C6 verifier replay offset overflows".to_owned())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated C6 verifier replay state".to_owned())?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed width")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed width")))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("fixed digest width"))
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let c0 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed width"));
        let c1 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed width"));
        if c0 >= P || c1 >= P {
            return Err("noncanonical C6 verifier replay field element".to_owned());
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

fn validate_bound_replay(replay: &C6BoundProductionVerifierReplay) -> Result<(usize, usize)> {
    let required = [
        replay.owner.setup_manifest_digest,
        replay.owner.reservation_digest,
        replay.owner.source_allocation_binding_digest,
        replay.owner.statement_digest,
        replay.certificate_digest,
        replay.owner.scope.connection_id,
        replay.owner.scope.response_nonce,
    ];
    if required.iter().any(|digest| *digest == [0; 32])
        || replay.owner.deltas[0] == replay.owner.deltas[1]
    {
        return Err("invalid C6 verifier replay binding".to_owned());
    }
    let sub = replay.owner.pools[0].sub_keys.len();
    let full = replay.owner.pools[0].full_keys.len();
    let production_geometry =
        (sub, full) == (C61_PRODUCTION_SUB_CORRELATIONS, C61_PRODUCTION_FULL_CORRELATIONS);
    let raw = sub
        .checked_add(
            full.checked_mul(2)
                .ok_or_else(|| "C6 verifier replay full-correlation count overflows".to_owned())?,
        )
        .ok_or_else(|| "C6 verifier replay raw count overflows".to_owned())?;
    if replay.owner.pools[1].sub_keys.len() != sub
        || replay.owner.pools[1].full_keys.len() != full
        || (production_geometry && raw != C6_BASELINE_RAW_CORRELATIONS as usize)
    {
        return Err("invalid C6 verifier replay pool geometry".to_owned());
    }
    Ok((sub, full))
}

fn encode_bound_replay(replay: &C6BoundProductionVerifierReplay) -> Result<Vec<u8>> {
    let (sub, full) = validate_bound_replay(replay)?;
    let mut out = ReplayWriter(REPLAY_MAGIC.to_vec());
    out.u16(REPLAY_VERSION);
    out.u16(0);
    for digest in [
        replay.owner.setup_manifest_digest,
        replay.owner.reservation_digest,
        replay.owner.source_allocation_binding_digest,
        replay.owner.statement_digest,
        replay.certificate_digest,
        replay.owner.scope.connection_id,
        replay.owner.scope.response_nonce,
    ] {
        out.0.extend_from_slice(&digest);
    }
    for delta in replay.owner.deltas {
        out.fp2(delta);
    }
    out.u32(u32::try_from(sub).map_err(|_| "C6 verifier replay sub count exceeds u32")?);
    out.u32(u32::try_from(full).map_err(|_| "C6 verifier replay full count exceeds u32")?);
    for pool in &replay.owner.pools {
        for key in pool.sub_keys.iter().chain(&pool.full_keys) {
            out.fp2(*key);
        }
    }
    let digest = blake3::hash(&out.0);
    out.0.extend_from_slice(digest.as_bytes());
    Ok(out.0)
}

fn decode_bound_replay(
    bytes: &[u8],
    expected_sub: usize,
    expected_full: usize,
) -> Result<C6BoundProductionVerifierReplay> {
    let keys = expected_sub
        .checked_add(expected_full)
        .and_then(|per_tape| per_tape.checked_mul(C6_MAC_COORDINATES))
        .ok_or_else(|| "C6 verifier replay key census overflows".to_owned())?;
    let expected_len = REPLAY_MAGIC
        .len()
        .checked_add(4 + 7 * 32 + 2 * 16 + 8 + 32)
        .and_then(|fixed| fixed.checked_add(keys.checked_mul(16)?))
        .ok_or_else(|| "C6 verifier replay byte census overflows".to_owned())?;
    if bytes.len() != expected_len {
        return Err("C6 verifier replay byte census mismatch".to_owned());
    }
    let (body, claimed_digest) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != claimed_digest {
        return Err("C6 verifier replay digest mismatch".to_owned());
    }
    let mut input = ReplayReader { bytes: body, offset: 0 };
    if input.take(REPLAY_MAGIC.len())? != REPLAY_MAGIC
        || input.u16()? != REPLAY_VERSION
        || input.u16()? != 0
    {
        return Err("C6 verifier replay header/version/reserved mismatch".to_owned());
    }
    let setup_manifest_digest = input.digest()?;
    let reservation_digest = input.digest()?;
    let source_allocation_binding_digest = input.digest()?;
    let statement_digest = input.digest()?;
    let certificate_digest = input.digest()?;
    let connection_id = input.digest()?;
    let response_nonce = input.digest()?;
    let deltas = [input.fp2()?, input.fp2()?];
    let sub = usize::try_from(input.u32()?).expect("u32 fits usize");
    let full = usize::try_from(input.u32()?).expect("u32 fits usize");
    if (sub, full) != (expected_sub, expected_full) {
        return Err("C6 verifier replay encoded geometry mismatch".to_owned());
    }
    let mut pools = Vec::with_capacity(C6_MAC_COORDINATES);
    for _ in 0..C6_MAC_COORDINATES {
        let mut sub_keys = Vec::with_capacity(sub);
        let mut full_keys = Vec::with_capacity(full);
        for _ in 0..sub {
            sub_keys.push(input.fp2()?);
        }
        for _ in 0..full {
            full_keys.push(input.fp2()?);
        }
        pools.push(VerifierPcgPool { sub_keys, full_keys });
    }
    if input.offset != body.len() {
        return Err("trailing C6 verifier replay bytes".to_owned());
    }
    if connection_id == [0; 32] || response_nonce == [0; 32] {
        return Err("zero C6 verifier replay connection scope".to_owned());
    }
    let owner = C6ProductionVerifierReplayOwner {
        setup_manifest_digest,
        reservation_digest,
        source_allocation_binding_digest,
        statement_digest,
        pools: pools.try_into().map_err(|_| "C6 verifier replay tape census mismatch")?,
        deltas,
        scope: ConnectionCorrelationScope::new(connection_id, response_nonce),
    };
    let replay = C6BoundProductionVerifierReplay { owner, certificate_digest };
    validate_bound_replay(&replay)?;
    if encode_bound_replay(&replay)? != bytes {
        return Err("noncanonical C6 verifier replay state".to_owned());
    }
    Ok(replay)
}

/// Paired source witness whose tape identities and ranges were fixed by the
/// production setup manifest and client reservation before either pool was
/// exposed to the response prover.
pub struct C6ProductionPairedSourceWitness {
    source: C6PairedSourceWitness,
    allocation_binding_digest: [u8; 32],
}

impl C6ProductionPairedSourceWitness {
    pub fn source(&self) -> &C6PairedSourceWitness {
        &self.source
    }

    pub fn allocation_binding_digest(&self) -> [u8; 32] {
        self.allocation_binding_digest
    }

    #[cfg(test)]
    pub(crate) fn from_reference(
        source: C6PairedSourceWitness,
        allocation_binding_digest: [u8; 32],
    ) -> Self {
        Self { source, allocation_binding_digest }
    }
}

impl C6ProductionPairedPcgAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn allocate(
        setup: &C6SetupManifest,
        reservation: C6SlotReservation,
        authorization_stores: [&ResponseAuthorizationStore; C6_MAC_COORDINATES],
        mut connections: [ProductionFaseDConnection; C6_MAC_COORDINATES],
        sub_correlations: usize,
        full_correlations: usize,
    ) -> Result<Self> {
        setup.validate().map_err(|error| error.to_string())?;
        reservation.validate().map_err(|error| error.to_string())?;
        let setup_manifest_digest = setup.digest().map_err(|error| error.to_string())?;
        let reservation_digest = reservation.digest().map_err(|error| error.to_string())?;
        if reservation.connection_id != setup.connection_id
            || reservation.setup_manifest_digest != setup_manifest_digest
        {
            return Err("C6 paired PCG reservation differs from setup manifest".to_owned());
        }
        let raw_count = u64::try_from(sub_correlations)
            .ok()
            .and_then(|sub| {
                u64::try_from(full_correlations)
                    .ok()
                    .and_then(|full| full.checked_mul(2))
                    .and_then(|full| sub.checked_add(full))
            })
            .ok_or_else(|| "C6 paired PCG raw count overflows".to_owned())?;
        if (sub_correlations, full_correlations)
            != (C61_PRODUCTION_SUB_CORRELATIONS, C61_PRODUCTION_FULL_CORRELATIONS)
            || raw_count != C6_BASELINE_RAW_CORRELATIONS
            || reservation.correlation_ranges.raw_count().map_err(|error| error.to_string())?
                != raw_count
        {
            return Err("C6 paired PCG allocation is not the frozen complete range".to_owned());
        }

        let connection_bindings =
            [connections[0].connection.binding(), connections[1].connection.binding()];
        for coordinate in 0..C6_MAC_COORDINATES {
            let expected_tape = setup.mac_tapes[coordinate];
            let range = reservation.correlation_ranges.coordinates[coordinate];
            let connection = &connections[coordinate];
            if connection_bindings[coordinate].connection_id != expected_tape.tape_id
                || connection_bindings[coordinate].stage_plan
                    != volta_pcg::FaseDStagePlan::TerminalOne
                || connection.production.ggm_prg != GgmPrg::Aes128Mmo
                || !connection.production.pcg_production_ready
                || expected_tape.raw_capacity < range.start.saturating_add(range.count)
            {
                return Err(format!(
                    "C6 production PCG tape {coordinate} differs from setup/range profile"
                ));
            }
        }

        for coordinate in 0..C6_MAC_COORDINATES {
            let response = connection_bindings[coordinate]
                .response_binding(reservation.nonce)
                .map_err(|error| error.to_string())?;
            connections[coordinate]
                .connection
                .begin_response(authorization_stores[coordinate], response)
                .map_err(|error| error.to_string())?;
        }

        let tensor_tag = paired_tensor_tag(setup_manifest_digest, reservation_digest);
        let mut allocated = Vec::with_capacity(C6_MAC_COORDINATES);
        for coordinate in 0..C6_MAC_COORDINATES {
            let binding = connection_bindings[coordinate];
            let domain = CorrelationDomain::new(
                binding.connection_id,
                reservation.nonce,
                u32::try_from(coordinate).map_err(|_| "C6 tape index overflows".to_owned())?,
                reservation.slot,
                u64::from(reservation.slot),
                tensor_tag,
            )
            .map_err(|error| error.to_string())?;
            allocated.push(
                connections[coordinate]
                    .allocate_pcg_pools(
                        reservation.correlation_ranges.coordinates[coordinate].stage,
                        sub_correlations,
                        full_correlations,
                        domain,
                    )
                    .map_err(|error| error.to_string())?,
            );
        }
        let [first, second]: [_; C6_MAC_COORDINATES] = allocated
            .try_into()
            .map_err(|_| "C6 paired PCG allocation census changed".to_owned())?;
        let allocations = [first.allocation, second.allocation];
        validate_allocations(reservation, &allocations)?;
        if first.verifier_delta == second.verifier_delta {
            return Err("C6 production PCG tapes reuse one verifier Delta".to_owned());
        }
        let scope = ConnectionCorrelationScope::new(setup.connection_id, reservation.nonce);
        let verifier_replay_pools = [first.verifier.clone(), second.verifier.clone()];
        let verifier_deltas = [first.verifier_delta, second.verifier_delta];
        let prover = [
            CorrelationStream::from_pcg_pool_connection(first.prover, scope),
            CorrelationStream::from_pcg_pool_connection(second.prover, scope),
        ];
        let verifier = [
            VerifierCtx::from_pcg_pool_connection(first.verifier_delta, first.verifier, scope),
            VerifierCtx::from_pcg_pool_connection(second.verifier_delta, second.verifier, scope),
        ];
        Ok(Self {
            setup_manifest_digest,
            reservation,
            reservation_digest,
            tape_ids: [setup.mac_tapes[0].tape_id, setup.mac_tapes[1].tape_id],
            allocations,
            prover,
            verifier,
            verifier_replay_pools: Some(verifier_replay_pools),
            verifier_deltas,
            verifier_scope: scope,
            connections,
            source_sealed: false,
            source_allocation_binding_digest: None,
        })
    }

    pub fn prover_streams_mut(&mut self) -> (&mut CorrelationStream, &mut CorrelationStream) {
        let [first, second] = &mut self.prover;
        (first, second)
    }

    /// Borrow both production prover tapes as the canonical paired owner.
    /// Complete-response drivers use this instead of constructing a second
    /// stream array or replaying one coordinate from a diagnostic seed.
    pub fn prover_streams_array_mut(&mut self) -> &mut [CorrelationStream; C6_MAC_COORDINATES] {
        &mut self.prover
    }

    pub fn reservation(&self) -> C6SlotReservation {
        self.reservation
    }

    pub fn verifier_contexts_mut(&mut self) -> (&mut VerifierCtx, &mut VerifierCtx) {
        let [first, second] = &mut self.verifier;
        (first, second)
    }

    /// Borrow both verifier contexts from the same paired allocation.
    pub fn verifier_contexts_array_mut(&mut self) -> &mut [VerifierCtx; C6_MAC_COORDINATES] {
        &mut self.verifier
    }

    pub fn seal_sources(
        &mut self,
        coordinates: [C6SourceCoordinate; C6_MAC_COORDINATES],
        schedule: &CorrScheduleAudit,
        source_schedule_digest: [u8; 32],
    ) -> Result<C6ProductionPairedSourceWitness> {
        if self.source_sealed
            || self.prover.iter().any(|stream| !stream.uses_pooled_pcg())
            || self.verifier.iter().any(|context| !context.uses_pooled_pcg())
        {
            return Err("C6 production paired sources are not live real-PCG owners".to_owned());
        }
        let source = C6PairedSourceWitness::new(
            self.tape_ids,
            coordinates,
            schedule,
            source_schedule_digest,
        )
        .map_err(|error| error.to_string())?;
        let allocation_binding_digest = allocation_binding_digest(
            self.setup_manifest_digest,
            self.reservation_digest,
            self.tape_ids,
            &self.allocations,
            source.pair_digest(),
        );
        self.source_sealed = true;
        self.source_allocation_binding_digest = Some(allocation_binding_digest);
        Ok(C6ProductionPairedSourceWitness { source, allocation_binding_digest })
    }

    /// Transfer the verifier-only replay seed after the source allocation is
    /// sealed. The provider response cannot obtain raw verifier keys from it.
    pub fn take_verifier_replay_owner(
        &mut self,
        statement_digest: [u8; 32],
    ) -> Result<C6ProductionVerifierReplayOwner> {
        if statement_digest == [0; 32] || !self.source_sealed {
            return Err("C6 verifier replay owner requested before statement/source binding".into());
        }
        let pools = self
            .verifier_replay_pools
            .take()
            .ok_or_else(|| "C6 verifier replay owner already transferred".to_owned())?;
        Ok(C6ProductionVerifierReplayOwner {
            setup_manifest_digest: self.setup_manifest_digest,
            reservation_digest: self.reservation_digest,
            source_allocation_binding_digest: self
                .source_allocation_binding_digest
                .ok_or_else(|| "C6 verifier replay source binding is absent".to_owned())?,
            statement_digest,
            pools,
            deltas: self.verifier_deltas,
            scope: self.verifier_scope,
        })
    }

    pub fn finish_success(mut self) -> Result<()> {
        if !self.source_sealed || self.verifier_replay_pools.is_some() {
            return Err(
                "C6 production paired attempt lacks sealed source/replay transfer".to_owned()
            );
        }
        for connection in &mut self.connections {
            connection.connection.finish_response_success().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

fn validate_allocations(
    reservation: C6SlotReservation,
    allocations: &[CorrelationAllocation; C6_MAC_COORDINATES],
) -> Result<()> {
    for coordinate in 0..C6_MAC_COORDINATES {
        let range = reservation.correlation_ranges.coordinates[coordinate];
        let allocation = &allocations[coordinate];
        if allocation.stage != range.stage
            || allocation.start != range.start
            || allocation.count != range.count
            || allocation.domain_digest.is_empty()
            || allocation.connection_allocation_digest.is_empty()
            || allocation.response_allocation_digest.is_empty()
        {
            return Err(format!(
                "C6 production PCG allocation {coordinate} differs from client reservation"
            ));
        }
    }
    Ok(())
}

fn paired_tensor_tag(setup_digest: [u8; 32], reservation_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/paired-pcg-domain/v1");
    hasher.update(&setup_digest);
    hasher.update(&reservation_digest);
    *hasher.finalize().as_bytes()
}

fn allocation_binding_digest(
    setup_digest: [u8; 32],
    reservation_digest: [u8; 32],
    tape_ids: [[u8; 32]; C6_MAC_COORDINATES],
    allocations: &[CorrelationAllocation; C6_MAC_COORDINATES],
    source_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SOURCE_BINDING_DOMAIN);
    hasher.update(&setup_digest);
    hasher.update(&reservation_digest);
    for coordinate in 0..C6_MAC_COORDINATES {
        hasher.update(&tape_ids[coordinate]);
        hasher.update(&allocations[coordinate].stage.to_le_bytes());
        hasher.update(&allocations[coordinate].start.to_le_bytes());
        hasher.update(&allocations[coordinate].count.to_le_bytes());
        hasher.update(allocations[coordinate].domain_digest.as_bytes());
        hasher.update(allocations[coordinate].connection_allocation_digest.as_bytes());
        hasher.update(allocations[coordinate].response_allocation_digest.as_bytes());
    }
    hasher.update(&source_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C6CorrelationRange, C6PairedCorrelationRanges, C6Workload};
    use volta_field::{Fp, Fp2};

    fn allocation(stage: u32, start: u64, count: u64) -> CorrelationAllocation {
        CorrelationAllocation {
            stage,
            start,
            count,
            domain_digest: "domain".to_owned(),
            connection_allocation_digest: "connection".to_owned(),
            response_allocation_digest: "response".to_owned(),
        }
    }

    fn reservation() -> C6SlotReservation {
        C6SlotReservation {
            connection_id: [0x11; 32],
            setup_manifest_digest: [0x12; 32],
            slot: 0,
            nonce: [0x13; 32],
            old_head_digest: [0x14; 32],
            predecessor_certificate_digest: [0; 32],
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    C6CorrelationRange { stage: 1, start: 7, count: C6_BASELINE_RAW_CORRELATIONS },
                    C6CorrelationRange { stage: 1, start: 19, count: C6_BASELINE_RAW_CORRELATIONS },
                ],
            },
            workload: C6Workload {
                prompt_tokens: 100,
                decode_tokens: 50,
                old_context: 0,
                new_context: 150,
            },
        }
    }

    fn replay_owner() -> C6ProductionVerifierReplayOwner {
        C6ProductionVerifierReplayOwner {
            setup_manifest_digest: [0x21; 32],
            reservation_digest: [0x22; 32],
            source_allocation_binding_digest: [0x23; 32],
            statement_digest: [0x24; 32],
            pools: [
                VerifierPcgPool {
                    sub_keys: vec![Fp2::new(Fp::new(1), Fp::new(2))],
                    full_keys: vec![Fp2::new(Fp::new(3), Fp::new(4))],
                },
                VerifierPcgPool {
                    sub_keys: vec![Fp2::new(Fp::new(5), Fp::new(6))],
                    full_keys: vec![Fp2::new(Fp::new(7), Fp::new(8))],
                },
            ],
            deltas: [Fp2::new(Fp::new(9), Fp::new(10)), Fp2::new(Fp::new(11), Fp::new(12))],
            scope: ConnectionCorrelationScope::new([0x25; 32], [0x26; 32]),
        }
    }

    #[test]
    fn exact_paired_allocations_match_both_client_ranges() {
        let reservation = reservation();
        let allocations = [
            allocation(1, 7, C6_BASELINE_RAW_CORRELATIONS),
            allocation(1, 19, C6_BASELINE_RAW_CORRELATIONS),
        ];
        validate_allocations(reservation, &allocations).unwrap();
        let mut wrong_start = allocations.clone();
        wrong_start[1].start += 1;
        assert!(validate_allocations(reservation, &wrong_start).is_err());
        let mut wrong_count = allocations;
        wrong_count[0].count -= 1;
        assert!(validate_allocations(reservation, &wrong_count).is_err());
    }

    #[test]
    fn verifier_replay_is_idempotent_only_for_the_bound_certificate() {
        assert!(replay_owner().bind_certificate([0; 32]).is_err());
        let digest = [0x31; 32];
        let replay = replay_owner().bind_certificate(digest).unwrap();
        let first = replay.fresh_contexts(digest).unwrap();
        let second = replay.fresh_contexts(digest).unwrap();
        assert!(first.iter().chain(&second).all(VerifierCtx::uses_pooled_pcg));
        assert_eq!(first[0].delta, second[0].delta);
        assert_eq!(first[1].delta, second[1].delta);
        assert!(replay.fresh_contexts([0x32; 32]).is_err());
    }

    #[test]
    fn verifier_replay_client_state_codec_is_strict_and_certificate_bound() {
        assert_eq!(C61_VERIFIER_REPLAY_STATE_BYTES, 160_469_204);
        let digest = [0x31; 32];
        let replay = replay_owner().bind_certificate(digest).unwrap();
        let bytes = replay.encode_client_state().unwrap();
        let decoded = decode_bound_replay(&bytes, 1, 1).unwrap();
        assert_eq!(decoded.certificate_digest(), digest);
        assert!(decoded.fresh_contexts(digest).is_ok());
        assert!(C6BoundProductionVerifierReplay::decode_client_state(&bytes).is_err());

        let mut corrupted = bytes.clone();
        corrupted[20] ^= 1;
        assert!(decode_bound_replay(&corrupted, 1, 1).is_err());

        let mut noncanonical = bytes;
        let first_delta = REPLAY_MAGIC.len() + 4 + 7 * 32;
        noncanonical[first_delta..first_delta + 8].copy_from_slice(&P.to_le_bytes());
        let body_len = noncanonical.len() - 32;
        let digest = *blake3::hash(&noncanonical[..body_len]).as_bytes();
        noncanonical[body_len..].copy_from_slice(&digest);
        assert!(decode_bound_replay(&noncanonical, 1, 1).is_err());
    }
}

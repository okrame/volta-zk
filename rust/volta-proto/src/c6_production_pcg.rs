//! Fail-closed bridge from the durable C6 paired reservation to two real
//! fase-D PCG tapes.

use crate::{
    C6PairedSourceWitness, C6SetupManifest, C6SlotReservation, C6SourceCoordinate,
    C6_BASELINE_RAW_CORRELATIONS, C6_MAC_COORDINATES,
};
use volta_mac::{ConnectionCorrelationScope, CorrScheduleAudit, CorrelationStream, VerifierCtx};
use volta_pcg::{
    CorrelationAllocation, CorrelationDomain, GgmPrg, ProductionFaseDConnection,
    ResponseAuthorizationStore,
};

const SOURCE_BINDING_DOMAIN: &str = "volta-zk/c6/production-paired-source/v1";

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
    connections: [ProductionFaseDConnection; C6_MAC_COORDINATES],
    source_sealed: bool,
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
        if raw_count != C6_BASELINE_RAW_CORRELATIONS
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
            connections,
            source_sealed: false,
        })
    }

    pub fn prover_streams_mut(&mut self) -> (&mut CorrelationStream, &mut CorrelationStream) {
        let [first, second] = &mut self.prover;
        (first, second)
    }

    pub fn reservation(&self) -> C6SlotReservation {
        self.reservation
    }

    pub fn verifier_contexts_mut(&mut self) -> (&mut VerifierCtx, &mut VerifierCtx) {
        let [first, second] = &mut self.verifier;
        (first, second)
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
        Ok(C6ProductionPairedSourceWitness { source, allocation_binding_digest })
    }

    pub fn finish_success(mut self) -> Result<()> {
        if !self.source_sealed {
            return Err("C6 production paired attempt has no sealed source witness".to_owned());
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
}

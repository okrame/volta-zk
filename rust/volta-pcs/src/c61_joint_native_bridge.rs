use volta_field::Fp2;
use volta_mac::{C6CanonicalTargetProfile, Transcript};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61JointNativeBodyBinding {
    pub cohort_id: u32,
    pub chain_slot: u16,
    pub claim_count: u32,
    pub typed_statement_digest: [u8; 32],
    pub tagless_body_digest: [u8; 32],
}

/// Incremental binder which deliberately has no challenge method. Only a
/// complete, canonically ordered set of native bodies can transition to
/// [`C61JointNativeBodiesFixed`].
pub struct C61JointNativeBodyScheduleBuilder<'a> {
    profile: &'a C6CanonicalTargetProfile,
    bindings: Vec<C61JointNativeBodyBinding>,
}

impl<'a> C61JointNativeBodyScheduleBuilder<'a> {
    pub fn new(profile: &'a C6CanonicalTargetProfile) -> Result<Self, String> {
        if profile.inference_profile_digest == [0; 32] || profile.cohorts.len() < 2 {
            return Err("C6NBR1 requires at least two typed native target cohorts".to_owned());
        }
        Ok(Self { profile, bindings: Vec::with_capacity(profile.cohorts.len()) })
    }

    pub fn bind_next(&mut self, binding: C61JointNativeBodyBinding) -> Result<(), String> {
        let expected = self
            .profile
            .cohorts
            .get(self.bindings.len())
            .ok_or_else(|| "C6NBR1 received too many native bodies".to_owned())?;
        let expected_count = u32::try_from(expected.canonical_nodes.len())
            .map_err(|_| "C6NBR1 cohort claim count exceeds u32".to_owned())?;
        if binding.cohort_id != expected.cohort_id
            || binding.chain_slot != expected.chain_slot
            || binding.claim_count != expected_count
            || binding.typed_statement_digest == [0; 32]
            || binding.tagless_body_digest == [0; 32]
        {
            return Err("C6NBR1 native body differs from its ordered target cohort".to_owned());
        }
        self.bindings.push(binding);
        Ok(())
    }

    pub fn finish(self) -> Result<C61JointNativeBodiesFixed, String> {
        if self.bindings.len() != self.profile.cohorts.len() {
            return Err("C6NBR1 cannot sample zeta before every native body is fixed".to_owned());
        }
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.1/joint-native-body-schedule/v1");
        hasher.update(&self.profile.inference_profile_digest);
        hasher.update(&self.profile.topology_digest);
        hasher.update(&self.profile.source_schedule_digest);
        hasher.update(&(self.bindings.len() as u32).to_le_bytes());
        for (cohort, binding) in self.profile.cohorts.iter().zip(&self.bindings) {
            hasher.update(&cohort.cohort_id.to_le_bytes());
            hasher.update(&cohort.chain_slot.to_le_bytes());
            hasher.update(&[cohort.polynomial_log2]);
            hasher.update(&cohort.claim_layout_digest);
            hasher.update(&binding.claim_count.to_le_bytes());
            hasher.update(&binding.typed_statement_digest);
            hasher.update(&binding.tagless_body_digest);
        }
        Ok(C61JointNativeBodiesFixed {
            schedule_digest: *hasher.finalize().as_bytes(),
            bindings: self.bindings,
        })
    }
}

pub struct C61JointNativeBodiesFixed {
    schedule_digest: [u8; 32],
    bindings: Vec<C61JointNativeBodyBinding>,
}

impl C61JointNativeBodiesFixed {
    pub fn schedule_digest(&self) -> [u8; 32] {
        self.schedule_digest
    }

    /// Derived statement/body digests are already available to both roles and
    /// add no provider wire. Zero-byte transcript events retain their strict
    /// ordering before the fresh interactive challenge.
    pub fn draw_zeta(self, transcript: &mut Transcript) -> C61JointNativeChallenge {
        for _ in &self.bindings {
            transcript.append("c6_joint_native_typed_statement", 0);
            transcript.append("c6_joint_native_tagless_body_digest", 0);
        }
        let zeta = transcript.challenge_fp2();
        let mut weight = Fp2::ONE;
        let mut cohort_weights = Vec::with_capacity(self.bindings.len());
        for _ in &self.bindings {
            cohort_weights.push(weight);
            weight = weight * zeta;
        }
        C61JointNativeChallenge { schedule_digest: self.schedule_digest, zeta, cohort_weights }
    }

    /// C6.2 binds the exact public statement and body digests before it
    /// derives `zeta`. These are verifier-reconstructible bytes, not wire.
    pub fn draw_c62_zeta(
        self,
        transcript: &mut Transcript,
    ) -> Result<C61JointNativeChallenge, String> {
        if !transcript.is_fiat_shamir() {
            return Err("C62FS1 zeta requires a Fiat--Shamir transcript".to_owned());
        }
        transcript.absorb_public_message("c62_joint_schedule_digest", &self.schedule_digest);
        for binding in &self.bindings {
            let mut encoded = Vec::with_capacity(74);
            encoded.extend_from_slice(&binding.cohort_id.to_le_bytes());
            encoded.extend_from_slice(&binding.chain_slot.to_le_bytes());
            encoded.extend_from_slice(&binding.claim_count.to_le_bytes());
            encoded.extend_from_slice(&binding.typed_statement_digest);
            encoded.extend_from_slice(&binding.tagless_body_digest);
            transcript.absorb_public_message("c62_joint_native_body_binding", &encoded);
        }
        let zeta = transcript.challenge_fp2();
        let mut weight = Fp2::ONE;
        let mut cohort_weights = Vec::with_capacity(self.bindings.len());
        for _ in &self.bindings {
            cohort_weights.push(weight);
            weight = weight * zeta;
        }
        Ok(C61JointNativeChallenge { schedule_digest: self.schedule_digest, zeta, cohort_weights })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61JointNativeChallenge {
    pub schedule_digest: [u8; 32],
    pub zeta: Fp2,
    pub cohort_weights: Vec<Fp2>,
}

#[cfg(test)]
mod tests {
    use volta_mac::{C6CanonicalTargetCohort, C6CanonicalTargetProfile};

    use super::*;

    fn profile(counts: &[usize]) -> C6CanonicalTargetProfile {
        C6CanonicalTargetProfile {
            inference_profile_digest: [0x51; 32],
            topology_digest: [0x52; 32],
            source_schedule_digest: [0x53; 32],
            cohorts: counts
                .iter()
                .enumerate()
                .map(|(index, &count)| C6CanonicalTargetCohort {
                    cohort_id: index as u32 + 1,
                    chain_slot: index as u16 + 1,
                    polynomial_log2: 12 - index as u8,
                    claim_layout_digest: [0x60 + index as u8; 32],
                    canonical_nodes: (0..count)
                        .map(|ordinal| 20 * index as u32 + ordinal as u32)
                        .collect(),
                })
                .collect(),
        }
    }

    fn binding(index: usize, count: usize) -> C61JointNativeBodyBinding {
        C61JointNativeBodyBinding {
            cohort_id: index as u32 + 1,
            chain_slot: index as u16 + 1,
            claim_count: count as u32,
            typed_statement_digest: [0x70 + index as u8; 32],
            tagless_body_digest: [0x80 + index as u8; 32],
        }
    }

    #[test]
    fn all_bodies_precede_one_role_symmetric_zeta() {
        let profile = profile(&[3, 2, 4]);
        let run = || {
            let mut builder = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
            for (index, count) in [3, 2, 4].into_iter().enumerate() {
                builder.bind_next(binding(index, count)).unwrap();
            }
            let fixed = builder.finish().unwrap();
            let digest = fixed.schedule_digest();
            let mut transcript = Transcript::new([0x91; 32]);
            let challenge = fixed.draw_zeta(&mut transcript);
            assert_eq!(transcript.total_bytes(), 0);
            assert_eq!(transcript.bytes_for("c6_joint_native_typed_statement"), 0);
            assert_eq!(challenge.schedule_digest, digest);
            challenge
        };
        let prover = run();
        let verifier = run();
        assert_eq!(prover, verifier);
        assert_eq!(prover.cohort_weights[0], Fp2::ONE);
        assert_eq!(prover.cohort_weights[1], prover.zeta);
        assert_eq!(prover.cohort_weights[2], prover.zeta * prover.zeta);
    }

    #[test]
    fn incomplete_reordered_or_changed_bodies_reject_before_zeta() {
        let profile = profile(&[3, 2]);
        let mut incomplete = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
        incomplete.bind_next(binding(0, 3)).unwrap();
        assert!(incomplete.finish().is_err());

        let mut reordered = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
        assert!(reordered.bind_next(binding(1, 2)).is_err());

        let mut changed = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
        let mut changed_binding = binding(0, 3);
        changed_binding.tagless_body_digest[0] ^= 1;
        changed.bind_next(changed_binding).unwrap();
        changed.bind_next(binding(1, 2)).unwrap();
        let changed_digest = changed.finish().unwrap().schedule_digest();

        let mut canonical = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
        canonical.bind_next(binding(0, 3)).unwrap();
        canonical.bind_next(binding(1, 2)).unwrap();
        assert_ne!(changed_digest, canonical.finish().unwrap().schedule_digest());
    }

    #[test]
    fn c62_zeta_is_public_deterministic_and_body_bound() {
        let profile = profile(&[3, 2]);
        let run = |changed: bool| {
            let mut builder = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
            for (index, count) in [3, 2].into_iter().enumerate() {
                let mut item = binding(index, count);
                if changed && index == 1 {
                    item.tagless_body_digest[0] ^= 1;
                }
                builder.bind_next(item).unwrap();
            }
            let mut transcript = Transcript::new_fiat_shamir([0xA1; 32]).unwrap();
            let challenge = builder.finish().unwrap().draw_c62_zeta(&mut transcript).unwrap();
            assert_eq!(transcript.total_bytes(), 0);
            assert_eq!(transcript.bytes_for("c62_joint_schedule_digest"), 0);
            challenge
        };
        let prover = run(false);
        let verifier = run(false);
        let changed = run(true);
        assert_eq!(prover, verifier);
        assert_ne!(prover.schedule_digest, changed.schedule_digest);
        assert_ne!(prover.zeta, changed.zeta);

        let mut private = Transcript::new([0xA1; 32]);
        let mut builder = C61JointNativeBodyScheduleBuilder::new(&profile).unwrap();
        builder.bind_next(binding(0, 3)).unwrap();
        builder.bind_next(binding(1, 2)).unwrap();
        assert!(builder.finish().unwrap().draw_c62_zeta(&mut private).is_err());
    }
}

//! CPU-only one-stage repeat-accumulate block-opening screen for C7.
//!
//! This is deliberately **not a PCS**.  It exercises the only surviving
//! one-pass sharing trick: each source contribution performs one range add at
//! the successor of its permuted position, then one query-only prefix pass
//! materializes the requested 141-symbol blocks.  A fixed-depth binary trie
//! makes every successor lookup exactly 64 steps, independent of the number
//! of requested blocks.
//!
//! The screen earns no protocol credit.  One-stage RA has no accepted
//! constant-relative-distance theorem for C7, the concrete affine interleaver
//! below is not a random interleaver, and constructing the complete committed
//! oracle still needs a forbidden reorder/model-sized temporary or nonmonotone
//! source access.  The diagonal expander is deterministic test arithmetic, not
//! a PRF, PCG, salt generator, or production correlation source.
//!
//! For `n` packed weights, repetition `r`, `U` requested leaves, logical
//! width `g = 141`, and `V <= U*g` in-range queried symbols, the exact counted
//! work is: one source pass, `n` increasing reads / `2n` source bytes / `n`
//! i16 decodes; `nr` permutations, diagonals, field multiplies, and successor
//! queries; `64nr` successor-trie steps; `64V` trie-insertion steps;
//! `range_adds + misses = nr`; and `U*g` prefix additions.  Thus this screen is
//! `O(64*r*n + 64*U*g)` with no `n`-sized scratch or codeword.  It must never
//! be reported as a PCS or as `C7_CPU_REFERENCE_PASS`.

use std::mem::size_of;

use volta_field::Fp;

pub const C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS: usize = 141;
const C7_RA_SCREEN_SUCCESSOR_STEPS: u64 = 64;
const NO_NODE: u32 = u32::MAX;

/// A concrete, allocation-free permutation used only by the CPU screen.
///
/// `gcd(multiplier, modulus) = 1` makes `a*x+b mod modulus` a permutation.
/// Its structure is exactly why it receives no ERA/RA distance credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7RaScreenAffineInterleaver {
    modulus: u64,
    multiplier: u64,
    shift: u64,
}

impl C7RaScreenAffineInterleaver {
    pub fn new(modulus: u64, multiplier: u64, shift: u64) -> Result<Self, String> {
        if modulus == 0 || multiplier == 0 || gcd(multiplier, modulus) != 1 {
            return Err("C7 RA screen interleaver is not a permutation".to_owned());
        }
        Ok(Self { modulus, multiplier: multiplier % modulus, shift: shift % modulus })
    }

    #[inline]
    fn position(self, occurrence: u64) -> u64 {
        debug_assert!(occurrence < self.modulus);
        ((u128::from(self.multiplier) * u128::from(occurrence) + u128::from(self.shift))
            % u128::from(self.modulus)) as u64
    }
}

/// Exact logical counters for the borrowed-slice CPU screen.
///
/// `packed_source_opens/read_calls` describe logical accesses to the single
/// borrowed `&[i16]`; they are not filesystem syscall measurements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C7RaBatchOpenScreenAudit {
    pub source_symbols: u64,
    pub repetition: u64,
    pub queried_leaves: u64,
    pub queried_symbols: u64,
    pub valid_queried_symbols: u64,
    pub padding_symbols: u64,
    pub packed_source_opens: u64,
    pub packed_source_passes: u64,
    pub packed_source_read_calls: u64,
    pub packed_source_bytes_read: u64,
    pub source_offsets_strictly_increasing: bool,
    pub backward_seeks_or_reopens: u64,
    pub i16_decodes: u64,
    pub permutation_evaluations: u64,
    pub diagonal_evaluations: u64,
    pub query_trie_insert_steps: u64,
    pub successor_queries: u64,
    pub successor_trie_steps: u64,
    pub source_linear_fp_muls: u64,
    pub source_linear_range_adds: u64,
    pub successor_misses: u64,
    pub query_prefix_fp_adds: u64,
    pub trie_nodes: u64,
    pub trie_capacity_nodes: u64,
    pub values_capacity_symbols: u64,
    pub output_index_capacity: u64,
    pub output_bytes: u64,
    pub peak_logical_scratch_and_output_bytes: u64,
    pub model_linear_scratch_write_bytes: u64,
    pub complete_codeword_bytes: u64,
    pub expanded_weight_bytes: u64,
    pub screen_only_not_pcs: bool,
    pub c7_cpu_reference_pass: bool,
    pub distance_gate_passed: bool,
    pub setup_gate_passed: bool,
}

impl C7RaBatchOpenScreenAudit {
    /// Fail closed if a counter or the intentionally negative disposition is
    /// mutated.  This validates the screen shape, not PCS security.
    pub fn validate_screen_shape(&self) -> bool {
        let Some(occurrences) = self.source_symbols.checked_mul(self.repetition) else {
            return false;
        };
        let Some(source_bytes) = self.source_symbols.checked_mul(size_of::<i16>() as u64) else {
            return false;
        };
        let Some(trie_steps) = occurrences.checked_mul(C7_RA_SCREEN_SUCCESSOR_STEPS) else {
            return false;
        };
        let Some(insert_steps) =
            self.valid_queried_symbols.checked_mul(C7_RA_SCREEN_SUCCESSOR_STEPS)
        else {
            return false;
        };
        let Some(payload_bytes) = self.queried_symbols.checked_mul(size_of::<Fp>() as u64) else {
            return false;
        };
        let Some(index_bytes) = self.queried_leaves.checked_mul(size_of::<u64>() as u64) else {
            return false;
        };
        let Some(values_allocation_bytes) =
            self.values_capacity_symbols.checked_mul(size_of::<Fp>() as u64)
        else {
            return false;
        };
        let Some(trie_allocation_bytes) =
            self.trie_capacity_nodes.checked_mul(size_of::<SuccessorNode>() as u64)
        else {
            return false;
        };
        let Some(index_allocation_bytes) =
            self.output_index_capacity.checked_mul(size_of::<u64>() as u64)
        else {
            return false;
        };
        let Some(working_peak) = values_allocation_bytes.checked_add(trie_allocation_bytes) else {
            return false;
        };
        let Some(returned_peak) = values_allocation_bytes.checked_add(index_allocation_bytes)
        else {
            return false;
        };
        self.queried_symbols
            == self
                .queried_leaves
                .checked_mul(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS as u64)
                .unwrap_or(u64::MAX)
            && self.valid_queried_symbols.checked_add(self.padding_symbols)
                == Some(self.queried_symbols)
            && self.packed_source_opens == 1
            && self.packed_source_passes == 1
            && self.packed_source_read_calls == self.source_symbols
            && self.packed_source_bytes_read == source_bytes
            && self.source_offsets_strictly_increasing
            && self.backward_seeks_or_reopens == 0
            && self.i16_decodes == self.source_symbols
            && self.permutation_evaluations == occurrences
            && self.diagonal_evaluations == occurrences
            && self.query_trie_insert_steps == insert_steps
            && self.successor_queries == occurrences
            && self.successor_trie_steps == trie_steps
            && self.source_linear_fp_muls == occurrences
            && self.source_linear_range_adds.checked_add(self.successor_misses) == Some(occurrences)
            && self.query_prefix_fp_adds == self.queried_symbols
            && self.trie_nodes <= self.trie_capacity_nodes
            && self.trie_nodes <= 1_u64.checked_add(insert_steps).unwrap_or(u64::MAX)
            && self.values_capacity_symbols >= self.queried_symbols
            && self.output_index_capacity >= self.queried_leaves
            && self.output_bytes == payload_bytes.checked_add(index_bytes).unwrap_or(u64::MAX)
            && self.peak_logical_scratch_and_output_bytes == working_peak.max(returned_peak)
            && self.model_linear_scratch_write_bytes == 0
            && self.complete_codeword_bytes == 0
            && self.expanded_weight_bytes == 0
            && self.screen_only_not_pcs
            && !self.c7_cpu_reference_pass
            && !self.distance_gate_passed
            && !self.setup_gate_passed
    }
}

/// Requested leaves in canonical order, flattened leaf-major without changing
/// the logical width of 141.  Payloads remain an internal screen value and are
/// not a C7 certificate codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C7RaBatchOpenScreenOutput {
    pub leaf_indices: Vec<u64>,
    pub values: Vec<Fp>,
    pub audit: C7RaBatchOpenScreenAudit,
}

impl C7RaBatchOpenScreenOutput {
    pub fn leaf(&self, offset: usize) -> Option<&[Fp]> {
        let start = offset.checked_mul(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS)?;
        let end = start.checked_add(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS)?;
        self.values.get(start..end)
    }
}

#[derive(Clone, Copy, Debug)]
struct SuccessorNode {
    children: [u32; 2],
    minimum_rank: u32,
}

impl SuccessorNode {
    fn new(rank: u32) -> Self {
        Self { children: [NO_NODE; 2], minimum_rank: rank }
    }
}

/// Exact 64-level successor index.  Its node count is `O(64 * U * 141)` and
/// every lookup performs 64 iterations even after its search path is absent.
struct SuccessorTrie {
    nodes: Vec<SuccessorNode>,
}

impl SuccessorTrie {
    fn new() -> Self {
        Self { nodes: vec![SuccessorNode::new(u32::MAX)] }
    }

    fn insert(&mut self, key: u64, rank: u32) -> Result<(), String> {
        let mut node = 0usize;
        self.nodes[node].minimum_rank = self.nodes[node].minimum_rank.min(rank);
        for bit_index in (0..64).rev() {
            let bit = ((key >> bit_index) & 1) as usize;
            let child = self.nodes[node].children[bit];
            let next = if child == NO_NODE {
                if self.nodes.len() >= NO_NODE as usize {
                    return Err("C7 RA screen successor trie exceeds sentinel-safe u32".to_owned());
                }
                let index = self.nodes.len() as u32;
                self.nodes.push(SuccessorNode::new(rank));
                self.nodes[node].children[bit] = index;
                index
            } else {
                child
            };
            node = next as usize;
            self.nodes[node].minimum_rank = self.nodes[node].minimum_rank.min(rank);
        }
        Ok(())
    }

    fn successor_rank(&self, key: u64) -> Option<u32> {
        let mut node = Some(0usize);
        let mut candidate = None;
        for bit_index in (0..64).rev() {
            if let Some(index) = node {
                let bit = ((key >> bit_index) & 1) as usize;
                if bit == 0 {
                    let right = self.nodes[index].children[1];
                    if right != NO_NODE {
                        candidate = Some(self.nodes[right as usize].minimum_rank);
                    }
                }
                let next = self.nodes[index].children[bit];
                node = (next != NO_NODE).then_some(next as usize);
            }
        }
        node.map(|index| self.nodes[index].minimum_rank).or(candidate)
    }
}

/// Execute the one-stage RA range-add screen over exactly one increasing
/// traversal of `packed_weights`.
pub fn c7_ra_batch_open_blocks_screen(
    packed_weights: &[i16],
    repetition: usize,
    leaf_indices: &[u64],
    interleaver: C7RaScreenAffineInterleaver,
    diagonal_seed: u64,
) -> Result<C7RaBatchOpenScreenOutput, String> {
    if packed_weights.is_empty() || repetition == 0 || leaf_indices.is_empty() {
        return Err("C7 RA screen requires nonempty source, repetition, and queries".to_owned());
    }
    if leaf_indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("C7 RA screen leaf indices are not canonical".to_owned());
    }
    let code_len = packed_weights
        .len()
        .checked_mul(repetition)
        .ok_or_else(|| "C7 RA screen code length overflows".to_owned())?;
    let code_len_u64 =
        u64::try_from(code_len).map_err(|_| "C7 RA screen code length exceeds u64".to_owned())?;
    if interleaver.modulus != code_len_u64 {
        return Err("C7 RA screen interleaver geometry differs".to_owned());
    }

    let queried_symbols = leaf_indices
        .len()
        .checked_mul(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS)
        .ok_or_else(|| "C7 RA screen query size overflows".to_owned())?;
    if queried_symbols > u32::MAX as usize {
        return Err("C7 RA screen query rank exceeds u32".to_owned());
    }
    let mut values = vec![Fp::ZERO; queried_symbols];
    let mut trie = SuccessorTrie::new();
    let mut valid_queried_symbols = 0usize;
    for (leaf_offset, &leaf_index) in leaf_indices.iter().enumerate() {
        let start = leaf_index
            .checked_mul(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS as u64)
            .ok_or_else(|| "C7 RA screen leaf offset overflows".to_owned())?;
        if start >= code_len_u64 {
            return Err("C7 RA screen leaf starts outside the codeword".to_owned());
        }
        for local in 0..C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS {
            let position = start
                .checked_add(local as u64)
                .ok_or_else(|| "C7 RA screen query position overflows".to_owned())?;
            if position < code_len_u64 {
                let rank = leaf_offset * C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS + local;
                trie.insert(position, rank as u32)?;
                valid_queried_symbols += 1;
            }
        }
    }

    let occurrences = code_len_u64;
    let mut range_adds = 0u64;
    let mut misses = 0u64;
    for (source_index, &weight) in packed_weights.iter().enumerate() {
        let lifted = Fp::from_i64(i64::from(weight));
        let occurrence_start = source_index
            .checked_mul(repetition)
            .ok_or_else(|| "C7 RA screen occurrence offset overflows".to_owned())?;
        for lane in 0..repetition {
            let occurrence = u64::try_from(occurrence_start + lane)
                .map_err(|_| "C7 RA screen occurrence exceeds u64".to_owned())?;
            let position = interleaver.position(occurrence);
            let term = lifted * screen_diagonal(diagonal_seed, position);
            if let Some(rank) = trie.successor_rank(position) {
                values[rank as usize] += term;
                range_adds += 1;
            } else {
                misses += 1;
            }
        }
    }

    let mut running = Fp::ZERO;
    for value in &mut values {
        running += *value;
        *value = running;
    }
    // Only the final logical leaf can be partial; zero padding is format data,
    // not an extension of the accumulator codeword.
    for (leaf_offset, &leaf_index) in leaf_indices.iter().enumerate() {
        let start = leaf_index
            .checked_mul(C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS as u64)
            .ok_or_else(|| "C7 RA screen padding offset overflows".to_owned())?;
        for local in 0..C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS {
            let position = start
                .checked_add(local as u64)
                .ok_or_else(|| "C7 RA screen padding position overflows".to_owned())?;
            if position >= code_len_u64 {
                values[leaf_offset * C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS + local] = Fp::ZERO;
            }
        }
    }

    let queried_symbols_u64 = queried_symbols as u64;
    let output_payload_bytes = queried_symbols_u64
        .checked_mul(size_of::<Fp>() as u64)
        .ok_or_else(|| "C7 RA screen output byte count overflows".to_owned())?;
    let output_index_bytes = (leaf_indices.len() as u64)
        .checked_mul(size_of::<u64>() as u64)
        .ok_or_else(|| "C7 RA screen output-index byte count overflows".to_owned())?;
    let output_bytes = output_payload_bytes
        .checked_add(output_index_bytes)
        .ok_or_else(|| "C7 RA screen total output byte count overflows".to_owned())?;
    let values_allocation_bytes = (values.capacity() as u64)
        .checked_mul(size_of::<Fp>() as u64)
        .ok_or_else(|| "C7 RA screen value allocation overflows".to_owned())?;
    let trie_bytes = (trie.nodes.capacity() as u64)
        .checked_mul(size_of::<SuccessorNode>() as u64)
        .ok_or_else(|| "C7 RA screen trie byte count overflows".to_owned())?;
    let working_peak = values_allocation_bytes
        .checked_add(trie_bytes)
        .ok_or_else(|| "C7 RA screen peak byte count overflows".to_owned())?;
    let trie_nodes = trie.nodes.len() as u64;
    let trie_capacity_nodes = trie.nodes.capacity() as u64;
    drop(trie);
    let output_leaf_indices = leaf_indices.to_vec();
    let output_index_allocation_bytes = (output_leaf_indices.capacity() as u64)
        .checked_mul(size_of::<u64>() as u64)
        .ok_or_else(|| "C7 RA screen output-index allocation overflows".to_owned())?;
    let returned_peak = values_allocation_bytes
        .checked_add(output_index_allocation_bytes)
        .ok_or_else(|| "C7 RA screen returned allocation overflows".to_owned())?;
    let peak = working_peak.max(returned_peak);
    let source_bytes = (packed_weights.len() as u64)
        .checked_mul(size_of::<i16>() as u64)
        .ok_or_else(|| "C7 RA screen source byte count overflows".to_owned())?;
    let successor_trie_steps = occurrences
        .checked_mul(C7_RA_SCREEN_SUCCESSOR_STEPS)
        .ok_or_else(|| "C7 RA screen successor step count overflows".to_owned())?;
    let query_trie_insert_steps = (valid_queried_symbols as u64)
        .checked_mul(C7_RA_SCREEN_SUCCESSOR_STEPS)
        .ok_or_else(|| "C7 RA screen insertion step count overflows".to_owned())?;
    let audit = C7RaBatchOpenScreenAudit {
        source_symbols: packed_weights.len() as u64,
        repetition: repetition as u64,
        queried_leaves: leaf_indices.len() as u64,
        queried_symbols: queried_symbols_u64,
        valid_queried_symbols: valid_queried_symbols as u64,
        padding_symbols: (queried_symbols - valid_queried_symbols) as u64,
        packed_source_opens: 1,
        packed_source_passes: 1,
        packed_source_read_calls: packed_weights.len() as u64,
        packed_source_bytes_read: source_bytes,
        source_offsets_strictly_increasing: true,
        backward_seeks_or_reopens: 0,
        i16_decodes: packed_weights.len() as u64,
        permutation_evaluations: occurrences,
        diagonal_evaluations: occurrences,
        query_trie_insert_steps,
        successor_queries: occurrences,
        successor_trie_steps,
        source_linear_fp_muls: occurrences,
        source_linear_range_adds: range_adds,
        successor_misses: misses,
        query_prefix_fp_adds: queried_symbols_u64,
        trie_nodes,
        trie_capacity_nodes,
        values_capacity_symbols: values.capacity() as u64,
        output_index_capacity: output_leaf_indices.capacity() as u64,
        output_bytes,
        peak_logical_scratch_and_output_bytes: peak,
        model_linear_scratch_write_bytes: 0,
        complete_codeword_bytes: 0,
        expanded_weight_bytes: 0,
        screen_only_not_pcs: true,
        c7_cpu_reference_pass: false,
        distance_gate_passed: false,
        setup_gate_passed: false,
    };
    if !audit.validate_screen_shape() {
        return Err("C7 RA screen internal counter reconciliation failed".to_owned());
    }
    Ok(C7RaBatchOpenScreenOutput { leaf_indices: output_leaf_indices, values, audit })
}

#[inline]
fn screen_diagonal(seed: u64, position: u64) -> Fp {
    // SplitMix-style deterministic fixture expansion.  This is intentionally
    // not named or treated as a cryptographic generator.
    let mut value = seed ^ position.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    let value = Fp::new(value);
    if value == Fp::ZERO {
        Fp::ONE
    } else {
        value
    }
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_encode(
        weights: &[i16],
        repetition: usize,
        interleaver: C7RaScreenAffineInterleaver,
        diagonal_seed: u64,
    ) -> Vec<Fp> {
        let mut codeword = vec![Fp::ZERO; weights.len() * repetition];
        for (source_index, &weight) in weights.iter().enumerate() {
            let lifted = Fp::from_i64(i64::from(weight));
            for lane in 0..repetition {
                let occurrence = (source_index * repetition + lane) as u64;
                let position = interleaver.position(occurrence) as usize;
                codeword[position] += lifted * screen_diagonal(diagonal_seed, position as u64);
            }
        }
        let mut running = Fp::ZERO;
        for value in &mut codeword {
            running += *value;
            *value = running;
        }
        codeword
    }

    fn expected_leaves(codeword: &[Fp], leaf_indices: &[u64]) -> Vec<Fp> {
        let mut expected =
            Vec::with_capacity(leaf_indices.len() * C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS);
        for &leaf in leaf_indices {
            let start = leaf as usize * C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS;
            for local in 0..C7_RA_SCREEN_LOGICAL_BLOCK_SYMBOLS {
                expected.push(codeword.get(start + local).copied().unwrap_or(Fp::ZERO));
            }
        }
        expected
    }

    #[test]
    fn one_pass_batch_matches_full_encoding_including_final_padding() {
        let weights =
            (0..211).map(|index| ((index as i32 * 37 % 509) - 254) as i16).collect::<Vec<_>>();
        let repetition = 4;
        let interleaver = C7RaScreenAffineInterleaver::new(844, 5, 17).unwrap();
        let leaves = [0, 2, 5];
        let opened = c7_ra_batch_open_blocks_screen(
            &weights,
            repetition,
            &leaves,
            interleaver,
            0xC7A0_0000_0000_0001,
        )
        .unwrap();
        let full = full_encode(&weights, repetition, interleaver, 0xC7A0_0000_0000_0001);

        assert_eq!(opened.values, expected_leaves(&full, &leaves));
        assert_eq!(opened.leaf(0), Some(&opened.values[..141]));
        assert_eq!(opened.audit.packed_source_bytes_read, 422);
        assert_eq!(opened.audit.permutation_evaluations, 844);
        assert_eq!(opened.audit.successor_trie_steps, 844 * 64);
        assert_eq!(opened.audit.query_trie_insert_steps, 421 * 64);
        assert_eq!(opened.audit.queried_symbols, 423);
        assert_eq!(opened.audit.valid_queried_symbols, 421);
        assert_eq!(opened.audit.padding_symbols, 2);
        assert!(opened.audit.validate_screen_shape());
        assert!(opened.audit.screen_only_not_pcs);
        assert!(!opened.audit.c7_cpu_reference_pass);
        assert!(!opened.audit.distance_gate_passed);
        assert!(!opened.audit.setup_gate_passed);
        assert!(opened.values[421..].iter().all(|value| *value == Fp::ZERO));
    }

    #[test]
    fn rejects_noncanonical_queries_and_nonpermuting_geometry() {
        assert!(C7RaScreenAffineInterleaver::new(16, 4, 0).is_err());
        let interleaver = C7RaScreenAffineInterleaver::new(16, 3, 1).unwrap();
        assert!(c7_ra_batch_open_blocks_screen(&[1, 2, 3, 4], 4, &[0, 0], interleaver, 7).is_err());
        assert!(c7_ra_batch_open_blocks_screen(&[1, 2, 3, 4], 4, &[1, 0], interleaver, 7).is_err());
        let wrong_geometry = C7RaScreenAffineInterleaver::new(17, 3, 1).unwrap();
        assert!(c7_ra_batch_open_blocks_screen(&[1, 2, 3, 4], 4, &[0], wrong_geometry, 7,).is_err());
    }

    #[test]
    fn source_mutation_changes_output_and_counter_mutation_fails_closed() {
        let mut weights = vec![0i16; 64];
        let interleaver = C7RaScreenAffineInterleaver::new(256, 5, 3).unwrap();
        let baseline = c7_ra_batch_open_blocks_screen(&weights, 4, &[0], interleaver, 11).unwrap();
        weights[0] = 1;
        let mutated = c7_ra_batch_open_blocks_screen(&weights, 4, &[0], interleaver, 11).unwrap();
        assert_ne!(baseline.values, mutated.values);

        let mut bad_audit = mutated.audit.clone();
        bad_audit.packed_source_bytes_read += 2;
        assert!(!bad_audit.validate_screen_shape());
        let mut understated_peak = mutated.audit.clone();
        understated_peak.peak_logical_scratch_and_output_bytes -= 1;
        assert!(!understated_peak.validate_screen_shape());
        let mut impossible_capacity = mutated.audit.clone();
        impossible_capacity.trie_nodes = impossible_capacity.trie_capacity_nodes + 1;
        assert!(!impossible_capacity.validate_screen_shape());
        let mut promoted = mutated.audit;
        promoted.distance_gate_passed = true;
        assert!(!promoted.validate_screen_shape());

        let mut falsely_credited = baseline.audit;
        falsely_credited.c7_cpu_reference_pass = true;
        assert!(!falsely_credited.validate_screen_shape());
    }
}

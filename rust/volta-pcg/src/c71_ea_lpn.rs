//! Bounded reference codecs for the selected C7.1 EA-LPN/cGGM candidate.
//!
//! This file fixes and tests only the public EAGen coin and the additive
//! cGGM accumulation identity. It is not an OT implementation, an Fp6 seed
//! bridge, or a composition theorem.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use volta_field::{Fp, Fp3, P};

const H_TAG: &[u8] = b"VOLTA-C71-DORY-CGGM-v1";
const EA_TAG: &[u8] = b"VOLTA-C71-DORY-EAGEN-v1";
const MAX_TRIALS: usize = 8;
const MAX_REFERENCE_HEIGHT: usize = 19;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    pub shake_calls: u64,
    pub absorbed_bytes: u64,
    pub squeezed_bytes: u64,
    pub fp_candidates: u64,
    pub fp3_additions: u64,
    pub fp3_subtractions: u64,
    pub fp3_multiplications: u64,
    pub fp3_by_fp_multiplications: u64,
    pub shake_object_bytes_peak: usize,
    pub codec_heap_capacity_bytes_peak: usize,
    pub recursive_frames_peak: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Workspace {
    pub serialized_persistent_bytes: usize,
    pub heap_live_len_bytes: usize,
    pub heap_capacity_bytes: usize,
    pub rust_value_size_bytes: usize,
    pub measured_stack_bytes: Option<usize>,
    pub complete_peak_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Shape,
    SamplerExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EaTerm {
    pub index: u64,
    pub coefficient: Fp,
}

/// Public EAGen row from the original public seed. Index and coefficient use
/// separate domain-separated XOFs, each with an eight-candidate fail-closed cap.
pub fn public_ea_row(
    seed: [u8; 32],
    row: u64,
    domain: u64,
    weight: usize,
) -> Result<(Vec<EaTerm>, Work), Error> {
    if domain == 0
        || weight == 0
        || weight > 11
        || weight > u32::MAX as usize
        || weight as u64 > domain
    {
        return Err(Error::Shape);
    }
    let limit = (u64::MAX as u128 + 1) / domain as u128 * domain as u128;
    let mut used = Vec::with_capacity(weight);
    let mut terms = Vec::with_capacity(weight);
    let mut work = Work::default();
    for term in 0..weight {
        let prefix = ea_prefix(seed, row, term as u32);
        let index = sample_u64(&prefix, b"index", &mut work, |candidate| {
            if candidate as u128 >= limit {
                return None;
            }
            let index = candidate % domain;
            if used.contains(&index) {
                None
            } else {
                used.push(index);
                Some(index)
            }
        })?;
        let coefficient = sample_u64(&prefix, b"coefficient", &mut work, |candidate| {
            (candidate != 0 && candidate < P).then(|| Fp::new(candidate))
        })?;
        terms.push(EaTerm { index, coefficient });
    }
    work.codec_heap_capacity_bytes_peak +=
        terms.capacity() * size_of::<EaTerm>() + used.capacity() * size_of::<u64>();
    Ok((terms, work))
}

/// Apply one public sparse EA row without materializing a dense matrix.
pub fn accumulate_ea_row(terms: &[EaTerm], mut value: impl FnMut(u64) -> Fp3) -> (Fp3, Work) {
    let mut result = Fp3::ZERO;
    let mut work = Work::default();
    for term in terms {
        result += value(term.index).mul_base(term.coefficient);
        work.fp3_by_fp_multiplications += 1;
        work.fp3_additions += 1;
    }
    (result, work)
}

pub fn ea_workspace(terms: &Vec<EaTerm>) -> Workspace {
    Workspace {
        serialized_persistent_bytes: 32 + 8,
        heap_live_len_bytes: terms.len() * size_of::<EaTerm>(),
        heap_capacity_bytes: terms.capacity() * size_of::<EaTerm>(),
        rust_value_size_bytes: size_of::<Vec<EaTerm>>() + size_of::<Work>(),
        measured_stack_bytes: None,
        complete_peak_bytes: None,
    }
}

/// One selected cGGM random-oracle evaluation. Numeric labels and Fp3 limbs
/// are fixed-width little endian; every limb has eight rejection trials.
pub fn cggm_h(
    nonce: [u8; 32],
    block: u64,
    level: u32,
    position: u64,
    node: Fp3,
) -> Result<(Fp3, Work), Error> {
    let mut input = Vec::with_capacity(H_TAG.len() + 32 + 8 + 4 + 8 + 24);
    input.extend_from_slice(H_TAG);
    input.extend_from_slice(&nonce);
    input.extend_from_slice(&block.to_le_bytes());
    input.extend_from_slice(&level.to_le_bytes());
    input.extend_from_slice(&position.to_le_bytes());
    input.extend_from_slice(&node.to_bytes());
    let mut reader = shake(&input);
    let mut work = Work {
        shake_calls: 1,
        absorbed_bytes: input.len() as u64,
        shake_object_bytes_peak: size_of::<Shake256>().max(size_of_val(&reader)),
        codec_heap_capacity_bytes_peak: input.capacity(),
        ..Default::default()
    };
    // Python fixes a separate 64-byte candidate slot for every limb.
    // Do not start the next limb immediately after an accepted candidate.
    let mut tape = [0u8; 3 * MAX_TRIALS * 8];
    reader.read(&mut tape);
    work.squeezed_bytes = tape.len() as u64;
    let limbs = sample_h_limbs(&tape, &mut work)?;
    Ok((Fp3::new(limbs[0], limbs[1], limbs[2]), work))
}

pub(crate) fn sample_h_limbs(tape: &[u8; 192], work: &mut Work) -> Result<[Fp; 3], Error> {
    let mut limbs = [Fp::ZERO; 3];
    for (limb, slot) in limbs.iter_mut().zip(tape.chunks_exact(64)) {
        let mut accepted = None;
        for bytes in slot.chunks_exact(8) {
            let candidate = u64::from_le_bytes(bytes.try_into().unwrap());
            work.fp_candidates += 1;
            if candidate < P {
                accepted = Some(Fp::new(candidate));
                break;
            }
        }
        *limb = accepted.ok_or(Error::SamplerExhausted)?;
    }
    Ok(limbs)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PuncturedKey {
    pub alpha: u64,
    pub height: usize,
    /// Off-path sibling root at each level, root first.
    pub siblings: Vec<Fp3>,
    /// The alpha leaf with Delta removed.
    pub alternative_leaf: Fp3,
}

/// Reference oracle over the sender's first split and a supplied leaf patch.
/// A distributed constructor cannot call this oracle: no role owns all inputs.
pub fn puncture(
    nonce: [u8; 32],
    block: u64,
    height: usize,
    alpha: u64,
    delta: Fp3,
    offset: Fp3,
    first_left: Fp3,
) -> Result<(PuncturedKey, Work), Error> {
    check_tree(height, alpha)?;
    let mut work = Work { fp3_subtractions: 1, ..Work::default() };
    let children = [first_left, offset - first_left];
    let mut position = bit(alpha, height, 0);
    let mut node = children[position as usize];
    let mut siblings = Vec::with_capacity(height);
    siblings.push(children[1 - position as usize]);
    for level in 1..height {
        let (left, h_work) = cggm_h(nonce, block, level as u32, position, node)?;
        add_work(&mut work, h_work);
        let right = node - left;
        work.fp3_subtractions += 1;
        let bit = bit(alpha, height, level);
        siblings.push(if bit == 0 { right } else { left });
        node = if bit == 0 { left } else { right };
        position = 2 * position + bit;
    }
    work.codec_heap_capacity_bytes_peak += siblings.capacity() * size_of::<Fp3>();
    Ok((
        PuncturedKey { alpha, height, siblings, alternative_leaf: node - delta },
        Work { fp3_subtractions: work.fp3_subtractions + 1, ..work },
    ))
}

/// Sender prefix accumulation with Dory's independent first split (k, offset-k).
pub fn acc(
    nonce: [u8; 32],
    block: u64,
    height: usize,
    omega: u64,
    offset: Fp3,
    first_left: Fp3,
) -> Result<(Fp3, Work), Error> {
    check_tree(height, omega)?;
    let children = [first_left, offset - first_left];
    let branch = bit(omega, height, 0);
    let node = children[branch as usize];
    let (mut result, mut work) = if height == 1 {
        (node, Work::default())
    } else {
        prefix_from_root(
            nonce,
            block,
            1,
            branch,
            height - 1,
            omega & ((1u64 << (height - 1)) - 1),
            node,
        )?
    };
    work.fp3_subtractions += 1;
    if branch == 1 {
        result += first_left;
        work.fp3_additions += 1;
    }
    Ok((result, work))
}

/// Receiver accumulation over the punctured tree. It equals the sender
/// prefix with Delta removed exactly when `omega >= alpha`.
pub fn punc_acc(
    nonce: [u8; 32],
    block: u64,
    omega: u64,
    key: &PuncturedKey,
) -> Result<(Fp3, Work, Workspace), Error> {
    check_tree(key.height, omega)?;
    check_tree(key.height, key.alpha)?;
    if key.siblings.len() != key.height {
        return Err(Error::Shape);
    }
    let mut on_path = vec![Fp3::ZERO; key.height + 1];
    let (result, work) = punc_acc_borrowed(
        nonce,
        block,
        omega,
        key.height,
        key.alpha,
        key.alternative_leaf,
        |level| key.siblings[level],
        &mut on_path,
    )?;
    Ok((result, work, workspace(key, &on_path)))
}

pub(crate) fn punc_acc_borrowed(
    nonce: [u8; 32],
    block: u64,
    omega: u64,
    height: usize,
    alpha: u64,
    alternative_leaf: Fp3,
    sibling_at: impl Fn(usize) -> Fp3,
    on_path: &mut [Fp3],
) -> Result<(Fp3, Work), Error> {
    check_tree(height, omega)?;
    check_tree(height, alpha)?;
    if on_path.len() != height + 1 {
        return Err(Error::Shape);
    }
    // Sums of the modified on-path subtrees, bottom-up. The alpha leaf is
    // the only changed leaf, so this reconstructs without Delta or root.
    on_path[height] = alternative_leaf;
    let mut work = Work::default();
    for level in (0..height).rev() {
        on_path[level] = on_path[level + 1] + sibling_at(level);
        work.fp3_additions += 1;
    }

    let mut result = Fp3::ZERO;
    let mut position = 0u64;
    for level in 0..height {
        let alpha_bit = bit(alpha, height, level);
        let omega_bit = bit(omega, height, level);
        let left = if alpha_bit == 0 { on_path[level + 1] } else { sibling_at(level) };
        if omega_bit == 1 {
            result += left;
            work.fp3_additions += 1;
        }
        if omega_bit != alpha_bit {
            let sibling = sibling_at(level);
            let remaining = height - level - 1;
            let suffix = omega & ((1u64 << remaining) - 1);
            let (tail, tail_work) = if remaining == 0 {
                (sibling, Work::default())
            } else {
                prefix_from_root(
                    nonce,
                    block,
                    level + 1,
                    2 * position + omega_bit,
                    remaining,
                    suffix,
                    sibling,
                )?
            };
            add_work(&mut work, tail_work);
            result += tail;
            work.fp3_additions += 1;
            return Ok((result, work));
        }
        position = 2 * position + alpha_bit;
    }
    result += alternative_leaf;
    work.fp3_additions += 1;
    Ok((result, work))
}

fn prefix_from_root(
    nonce: [u8; 32],
    block: u64,
    start_level: usize,
    mut position: u64,
    height: usize,
    omega: u64,
    mut node: Fp3,
) -> Result<(Fp3, Work), Error> {
    check_tree(height, omega)?;
    let mut result = Fp3::ZERO;
    let mut work = Work::default();
    for local in 0..height {
        let level = start_level + local;
        let (left, h_work) = cggm_h(nonce, block, level as u32, position, node)?;
        add_work(&mut work, h_work);
        let right = node - left;
        work.fp3_subtractions += 1;
        let branch = bit(omega, height, local);
        if branch == 1 {
            result += left;
            work.fp3_additions += 1;
        }
        node = if branch == 0 { left } else { right };
        position = 2 * position + branch;
    }
    result += node;
    work.fp3_additions += 1;
    Ok((result, work))
}

fn sample_u64<T>(
    prefix: &Vec<u8>,
    kind: &[u8],
    work: &mut Work,
    mut accept: impl FnMut(u64) -> Option<T>,
) -> Result<T, Error> {
    let mut input = Vec::with_capacity(prefix.len() + kind.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(kind);
    let mut reader = shake(&input);
    work.shake_calls += 1;
    work.absorbed_bytes += input.len() as u64;
    work.shake_object_bytes_peak =
        work.shake_object_bytes_peak.max(size_of::<Shake256>().max(size_of_val(&reader)));
    work.codec_heap_capacity_bytes_peak =
        work.codec_heap_capacity_bytes_peak.max(prefix.capacity() + input.capacity());
    for _ in 0..MAX_TRIALS {
        let candidate = read_u64(&mut reader);
        work.fp_candidates += 1;
        work.squeezed_bytes += 8;
        if let Some(value) = accept(candidate) {
            return Ok(value);
        }
    }
    Err(Error::SamplerExhausted)
}

fn ea_prefix(seed: [u8; 32], row: u64, term: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(EA_TAG.len() + 32 + 8 + 4);
    result.extend_from_slice(EA_TAG);
    result.extend_from_slice(&seed);
    result.extend_from_slice(&row.to_le_bytes());
    result.extend_from_slice(&term.to_le_bytes());
    result
}

fn shake(input: &[u8]) -> impl XofReader {
    let mut hash = Shake256::default();
    hash.update(input);
    hash.finalize_xof()
}

fn read_u64(reader: &mut impl XofReader) -> u64 {
    let mut bytes = [0; 8];
    reader.read(&mut bytes);
    u64::from_le_bytes(bytes)
}

fn bit(value: u64, height: usize, level: usize) -> u64 {
    value >> (height - 1 - level) & 1
}

fn check_tree(height: usize, index: u64) -> Result<(), Error> {
    if height == 0 || height > MAX_REFERENCE_HEIGHT || index >= 1u64 << height {
        Err(Error::Shape)
    } else {
        Ok(())
    }
}

fn workspace(key: &PuncturedKey, on_path: &Vec<Fp3>) -> Workspace {
    Workspace {
        serialized_persistent_bytes: 4 + 8 + key.height * Fp3::ENCODED_BYTES + Fp3::ENCODED_BYTES,
        heap_live_len_bytes: (key.siblings.len() + on_path.len()) * size_of::<Fp3>(),
        heap_capacity_bytes: (key.siblings.capacity() + on_path.capacity()) * size_of::<Fp3>(),
        rust_value_size_bytes: size_of::<PuncturedKey>()
            + size_of::<Vec<Fp3>>()
            + size_of::<Work>(),
        measured_stack_bytes: None,
        complete_peak_bytes: None,
    }
}

pub(crate) fn add_work(total: &mut Work, add: Work) {
    total.shake_calls += add.shake_calls;
    total.absorbed_bytes += add.absorbed_bytes;
    total.squeezed_bytes += add.squeezed_bytes;
    total.fp_candidates += add.fp_candidates;
    total.fp3_additions += add.fp3_additions;
    total.fp3_subtractions += add.fp3_subtractions;
    total.fp3_multiplications += add.fp3_multiplications;
    total.fp3_by_fp_multiplications += add.fp3_by_fp_multiplications;
    total.shake_object_bytes_peak = total.shake_object_bytes_peak.max(add.shake_object_bytes_peak);
    total.codec_heap_capacity_bytes_peak =
        total.codec_heap_capacity_bytes_peak.max(add.codec_heap_capacity_bytes_peak);
    total.recursive_frames_peak = total.recursive_frames_peak.max(add.recursive_frames_peak);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(x: u64) -> Fp3 {
        Fp3::new(Fp::new(x), Fp::new(3 * x + 1), Fp::new(5 * x + 2))
    }

    #[test]
    fn ea_row_is_deterministic_distinct_nonzero_and_domain_separated() {
        let (a, work) = public_ea_row([7; 32], 9, 64, 11).unwrap();
        let (b, _) = public_ea_row([7; 32], 9, 64, 11).unwrap();
        let (other, _) = public_ea_row([7; 32], 10, 64, 11).unwrap();
        let expected = [
            (55, 11_087_925_567_377_319_200),
            (5, 15_808_995_484_419_125_314),
            (51, 16_673_530_166_491_115_247),
            (19, 2_233_152_189_590_842_671),
            (39, 1_887_246_545_861_739_996),
            (34, 5_558_277_317_930_113_838),
            (53, 17_097_341_632_565_598_256),
            (8, 3_669_040_890_854_888_716),
            (47, 16_375_571_540_537_656_497),
            (36, 11_441_933_041_787_274_637),
            (14, 17_975_781_859_613_360_210),
        ];
        assert_eq!(
            a.iter().map(|x| (x.index, x.coefficient.value())).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(a, b);
        assert_ne!(a, other);
        assert!(a.iter().enumerate().all(|(i, x)| !a[..i].iter().any(|y| y.index == x.index)));
        assert!(a.iter().all(|x| x.coefficient != Fp::ZERO));
        assert_eq!(work.shake_calls, 22);
        assert_eq!(work.fp_candidates, 22);
        let (sum, apply) = accumulate_ea_row(&a, |index| f(index + 1));
        let direct = a
            .iter()
            .fold(Fp3::ZERO, |acc, term| acc + f(term.index + 1).mul_base(term.coefficient));
        assert_eq!(sum, direct);
        assert_eq!(apply.fp3_by_fp_multiplications, 11);
        let space = ea_workspace(&a);
        assert_eq!(space.serialized_persistent_bytes, 40);
        assert_eq!(space.heap_live_len_bytes, 176);
        assert_eq!(space.measured_stack_bytes, None);
        assert_eq!(space.complete_peak_bytes, None);
    }

    #[test]
    fn cggm_h_matches_python_reference_vectors() {
        let vectors = [
            (
                0,
                0,
                Fp3::new(Fp::new(17), Fp::new(52), Fp::new(87)),
                [12_552_674_446_361_369_531, 17_287_719_716_439_380_213, 3_166_462_483_984_546_071],
            ),
            (
                3,
                5,
                Fp3::new(Fp::new(1), Fp::new(2), Fp::new(3)),
                [10_365_856_843_759_094_983, 13_552_541_866_499_548_177, 2_791_103_846_626_352_577],
            ),
        ];
        for (level, position, node, expected) in vectors {
            let (got, work) = cggm_h([13; 32], 3, level, position, node).unwrap();
            assert_eq!([got.c0.value(), got.c1.value(), got.c2.value()], expected);
            assert_eq!(work.shake_calls, 1);
            assert_eq!(work.absorbed_bytes, 98);
            assert_eq!(work.squeezed_bytes, 192);
            assert_eq!(work.fp_candidates, 3);
        }
    }

    #[test]
    fn punctured_accumulation_matches_original_coin_tree() {
        let nonce = [13; 32];
        for height in 1..=7 {
            for alpha in 0..1u64 << height {
                let delta = f(101 + alpha);
                let offset = f(17 + alpha);
                let first_left = f(53 + alpha);
                let (key, setup_work) =
                    puncture(nonce, 3, height, alpha, delta, offset, first_left).unwrap();
                assert_eq!(setup_work.shake_calls, height as u64 - 1);
                let mut leaves = vec![first_left, offset - first_left];
                for level in 1..height {
                    leaves = leaves
                        .iter()
                        .enumerate()
                        .flat_map(|(position, &node)| {
                            let left =
                                cggm_h(nonce, 3, level as u32, position as u64, node).unwrap().0;
                            [left, node - left]
                        })
                        .collect();
                }
                let mut prefix = Fp3::ZERO;
                for omega in 0..1u64 << height {
                    prefix += leaves[omega as usize];
                    let (sender, work) = acc(nonce, 3, height, omega, offset, first_left).unwrap();
                    assert_eq!(sender, prefix);
                    assert_eq!(work.shake_calls, height as u64 - 1);
                    let (receiver, _, space) = punc_acc(nonce, 3, omega, &key).unwrap();
                    let expected = if omega >= alpha { delta } else { Fp3::ZERO };
                    assert_eq!(sender - receiver, expected);
                    assert_eq!(space.serialized_persistent_bytes, 12 + (height + 1) * 24);
                    assert_eq!(space.complete_peak_bytes, None);
                }
                assert_eq!(prefix, offset);
            }
        }
        eprintln!("C71_CGGM_FIRST_SPLIT heights=1..7 independent_k=true distributed_setup=false");
    }

    #[test]
    fn codecs_fail_closed_on_bad_shapes() {
        assert_eq!(public_ea_row([1; 32], 0, 11, 11), Err(Error::SamplerExhausted));
        let mut work = Work::default();
        assert_eq!(sample_h_limbs(&[255; 192], &mut work), Err(Error::SamplerExhausted));
        assert_eq!(work.fp_candidates, 8);
        assert_eq!(public_ea_row([0; 32], 0, 4, 5), Err(Error::Shape));
        assert_eq!(public_ea_row([0; 32], 0, 64, 12), Err(Error::Shape));
        assert!(puncture([0; 32], 0, 20, 0, f(1), f(2), f(3)).is_err());
    }
}

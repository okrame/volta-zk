use crate::c71_ea_lpn::{add_work, Error, Work};
use volta_field::{Fp, Fp3};

pub(super) struct Term {
    pub index: u64,
    pub row: usize,
    pub coefficient: Fp,
}

pub(super) fn visit(
    height: usize,
    terms: &[Term],
    node: Fp3,
    prefix: Fp3,
    mut split: impl FnMut(usize, u64, Fp3) -> Result<(Fp3, Work), Error>,
    mut emit: impl FnMut(&Term, Fp3),
) -> Result<Work, Error> {
    if height == 0
        || height > 19
        || terms.is_empty()
        || terms.windows(2).any(|pair| pair[0].index > pair[1].index)
        || terms[0].index >> height != terms[terms.len() - 1].index >> height
    {
        return Err(Error::Shape);
    }
    fn descend(
        height: usize,
        level: usize,
        position: u64,
        terms: &[Term],
        node: Fp3,
        prefix: Fp3,
        split: &mut impl FnMut(usize, u64, Fp3) -> Result<(Fp3, Work), Error>,
        emit: &mut impl FnMut(&Term, Fp3),
    ) -> Result<Work, Error> {
        let mut work = Work { recursive_frames_peak: level + 1, ..Work::default() };
        if level == height {
            let value = prefix + node;
            work.fp3_additions += 1;
            for term in terms {
                emit(term, value);
            }
            return Ok(work);
        }
        let (left, split_work) = split(level, position, node)?;
        add_work(&mut work, split_work);
        let boundary = terms.partition_point(|term| {
            work.public_index_comparisons += 1;
            (term.index >> (height - level - 1)) & 1 == 0
        });
        let (lower, upper) = terms.split_at(boundary);
        if !lower.is_empty() {
            add_work(
                &mut work,
                descend(height, level + 1, 2 * position, lower, left, prefix, split, emit)?,
            );
        }
        if !upper.is_empty() {
            add_work(
                &mut work,
                descend(
                    height,
                    level + 1,
                    2 * position + 1,
                    upper,
                    node - left,
                    prefix + left,
                    split,
                    emit,
                )?,
            );
            work.fp3_subtractions += 1;
            work.fp3_additions += 1;
        }
        Ok(work)
    }
    let mut work = descend(height, 0, 0, terms, node, prefix, &mut split, &mut emit)?;
    work.public_index_comparisons += terms.len() as u64;
    Ok(work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_ea_lpn::{acc, cggm_h, punc_acc, puncture};

    #[test]
    fn c71_seed6_trie_matches_every_original_prefix_with_duplicates() {
        let nonce = [13; 32];
        let block = 7;
        let field = |value| Fp3::new(Fp::new(value), Fp::new(value + 1), Fp::new(value + 2));
        for height in 1..=6 {
            let offset = field(17);
            let first = field(29);
            let prefix = field(53);
            let delta = field(101);
            let terms: Vec<_> = (0..1 << height)
                .flat_map(|index| [index, index])
                .map(|index| Term {
                    index: (block << height) + index,
                    row: index as usize,
                    coefficient: Fp::ONE,
                })
                .collect();
            let mut sender = vec![Fp3::ZERO; 1 << height];
            let work = visit(
                height,
                &terms,
                offset,
                prefix,
                |level, position, node| {
                    if level == 0 {
                        Ok((first, Work::default()))
                    } else {
                        cggm_h(nonce, block, level as u32, position, node)
                    }
                },
                |term, value| {
                    sender[term.row] = value;
                },
            )
            .unwrap();
            assert_eq!(work.shake_calls, (1 << height) - 2);
            assert_eq!(work.recursive_frames_peak, height + 1);
            for alpha in 0..1 << height {
                let (key, _) = puncture(nonce, block, height, alpha, delta, offset, first).unwrap();
                let mut on_path = [Fp3::ZERO; 20];
                on_path[height] = key.alternative_leaf;
                for level in (0..height).rev() {
                    on_path[level] = on_path[level + 1] + key.siblings[level];
                }
                let mut receiver = vec![Fp3::ZERO; 1 << height];
                let receiver_work = visit(
                    height,
                    &terms,
                    on_path[0],
                    prefix,
                    |level, position, node| {
                        if position == alpha >> (height - level) {
                            let left = if (alpha >> (height - level - 1)) & 1 == 0 {
                                on_path[level + 1]
                            } else {
                                key.siblings[level]
                            };
                            Ok((left, Work::default()))
                        } else {
                            cggm_h(nonce, block, level as u32, position, node)
                        }
                    },
                    |term, value| {
                        receiver[term.row] = value;
                    },
                )
                .unwrap();
                assert!(receiver_work.shake_calls <= work.shake_calls);
                for omega in 0..1 << height {
                    assert_eq!(
                        sender[omega as usize],
                        prefix + acc(nonce, block, height, omega, offset, first).unwrap().0
                    );
                    assert_eq!(
                        receiver[omega as usize],
                        prefix + punc_acc(nonce, block, omega, &key).unwrap().0
                    );
                }
            }
        }
        let mut terms = vec![
            Term { index: 2, row: 0, coefficient: Fp::ONE },
            Term { index: 1, row: 0, coefficient: Fp::ONE },
        ];
        assert!(visit(
            2,
            &terms,
            Fp3::ZERO,
            Fp3::ZERO,
            |_, _, _| panic!("unordered terms used"),
            |_, _| {}
        )
        .is_err());
        terms[1].index = 4;
        assert!(visit(
            2,
            &terms,
            Fp3::ZERO,
            Fp3::ZERO,
            |_, _, _| panic!("cross-tree terms used"),
            |_, _| {}
        )
        .is_err());
        terms.truncate(1);
        assert_eq!(
            visit(
                2,
                &terms,
                Fp3::ZERO,
                Fp3::ZERO,
                |_, _, _| Err(Error::SamplerExhausted),
                |_, _| panic!("failed sampler emitted")
            ),
            Err(Error::SamplerExhausted)
        );
        println!("C71_SEED6_TRIE heights=1..6 every_puncture_and_prefix=true duplicate_queries=true distributed_setup=false");
    }
}

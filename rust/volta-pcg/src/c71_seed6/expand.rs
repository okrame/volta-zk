//! Reference expansion after F_EQ acceptance, with one monotone row cursor.
//! The public EA seed is derived from verified F_EQ openings. Pointwise and
//! bounded batch trie share one cursor; global transcript/proof remain open.
use super::{Error, ReceiverPending, SenderPending};
use crate::c71_ea_lpn::{acc, add_work, public_ea_row, punc_acc_borrowed, EaTerm, Work};
use crate::c71_seed6::{equality::Accepted, Fp3Words};
use volta_field::{Fp, Fp3};
use zeroize::{Zeroize, Zeroizing};

#[path = "trie.rs"]
mod trie;

pub(super) const BATCH: usize = 4096;

struct Stream {
    nonce: [u8; 32],
    seed: [u8; 32],
    height: usize,
    weight: usize,
    next: u64,
    limit: u64,
    domain: u64,
}

impl Stream {
    fn new(
        nonce: [u8; 32],
        seed: [u8; 32],
        blocks: usize,
        height: usize,
        weight: usize,
    ) -> Result<Self, Error> {
        if nonce == [0; 32] || blocks == 0 || blocks > 675 || height == 0 || height > 19 {
            return Err(Error::Shape);
        }
        let domain = (blocks as u64) << height;
        if seed == [0; 32] || weight == 0 || weight > 11 || weight as u64 > domain || domain < 5 {
            return Err(Error::Shape);
        }
        Ok(Self { nonce, seed, height, weight, next: 0, limit: domain / 5, domain })
    }

    fn terms(&mut self) -> Result<(Vec<EaTerm>, Work), Error> {
        if self.next >= self.limit {
            return Err(Error::Rejected);
        }
        let row = self.next;
        self.next = self.limit;
        let result =
            public_ea_row(self.seed, row, self.domain, self.weight).map_err(|_| Error::Rejected)?;
        self.next = row + 1;
        Ok(result)
    }

    fn batch_terms(&mut self, count: usize) -> Result<(Vec<trie::Term>, Work), Error> {
        if count == 0 || count > BATCH || count as u64 > self.limit - self.next {
            return Err(Error::Rejected);
        }
        let first = self.next;
        self.next = self.limit;
        let mut terms = Vec::with_capacity(count * self.weight);
        let mut work = Work::default();
        for row in 0..count {
            let (values, row_work) =
                public_ea_row(self.seed, first + row as u64, self.domain, self.weight)
                    .map_err(|_| Error::Rejected)?;
            add_work(&mut work, row_work);
            terms.extend(values.into_iter().map(|term| trie::Term {
                index: term.index,
                row,
                coefficient: term.coefficient,
            }));
        }
        terms.sort_unstable_by(|left, right| {
            work.public_index_comparisons += 1;
            left.index.cmp(&right.index)
        });
        self.next = first + count as u64;
        Ok((terms, work))
    }
}

pub(super) struct Sender {
    stream: Stream,
    delta: Zeroizing<Fp3Words>,
    roots: Zeroizing<Vec<[Fp3Words; 2]>>,
    pub(super) binding: [u8; 32],
    pub(super) work: Work,
}

pub(super) struct Receiver {
    stream: Stream,
    alpha: Zeroizing<Vec<u64>>,
    beta: Zeroizing<Vec<u64>>,
    keys: Zeroizing<Vec<Fp3Words>>,
    prefix_tags: Zeroizing<Vec<Fp3Words>>,
    pub(super) binding: [u8; 32],
    pub(super) work: Work,
    pub(super) base_mul_add_pairs: u64,
}

impl Sender {
    pub(super) fn new(accepted: Accepted<SenderPending>, weight: usize) -> Result<Self, Error> {
        let (pending, binding) = accepted.into_parts();
        let frozen = &pending.guard.frozen;
        let stream = Stream::new(pending.nonce, binding, frozen.blocks, frozen.height, weight)?;
        let mut roots = pending.roots;
        let mut prefix = Fp3::ZERO;
        for children in roots.iter_mut() {
            prefix += children[0].fp3() + children[1].fp3();
            children[1] = Fp3Words::from_fp3(prefix);
        }
        Ok(Self {
            stream,
            delta: pending.guard.seed.delta,
            roots,
            binding,
            work: Work { fp3_additions: 2 * frozen.blocks as u64, ..Work::default() },
        })
    }

    pub(super) fn next_row(&mut self) -> Result<[u64; 3], Error> {
        let result = (|| {
            let (terms, mut work) = self.stream.terms()?;
            let mut key = Fp3::ZERO;
            for term in terms {
                let block = (term.index >> self.stream.height) as usize;
                let omega = term.index & ((1 << self.stream.height) - 1);
                let roots = self.roots[block];
                let prefix = if block == 0 { Fp3::ZERO } else { self.roots[block - 1][1].fp3() };
                let (value, point_work) = acc(
                    self.stream.nonce,
                    block as u64,
                    self.stream.height,
                    omega,
                    roots[1].fp3() - prefix,
                    roots[0].fp3(),
                )
                .map_err(|_| Error::Rejected)?;
                add_work(&mut work, point_work);
                key += (value + prefix).mul_base(term.coefficient);
                work.fp3_by_fp_multiplications += 1;
                work.fp3_additions += 2;
                work.fp3_subtractions += 1;
            }
            add_work(&mut self.work, work);
            Ok([key.c0.value(), key.c1.value(), key.c2.value()])
        })();
        if result.is_err() {
            self.stream.next = self.stream.limit;
            self.delta.zeroize();
            self.roots.zeroize();
        }
        result
    }

    pub(super) fn delta(&self) -> Fp3 {
        self.delta.fp3()
    }

    pub(super) fn next_batch(&mut self, count: usize) -> Result<Zeroizing<Vec<[u64; 3]>>, Error> {
        let result = (|| {
            let (terms, mut work) = self.stream.batch_terms(count)?;
            let mut output = Zeroizing::new(vec![[0; 3]; count]);
            let mut remaining = terms.as_slice();
            while let Some(first) = remaining.first() {
                let block = (first.index >> self.stream.height) as usize;
                let boundary = remaining.partition_point(|term| {
                    work.public_index_comparisons += 1;
                    term.index >> self.stream.height == block as u64
                });
                let (queries, rest) = remaining.split_at(boundary);
                remaining = rest;
                let roots = self.roots[block];
                let prefix = if block == 0 { Fp3::ZERO } else { self.roots[block - 1][1].fp3() };
                let tree_work = trie::visit(
                    self.stream.height,
                    queries,
                    roots[1].fp3() - prefix,
                    prefix,
                    |level, position, node| {
                        if level == 0 {
                            Ok((roots[0].fp3(), Work::default()))
                        } else {
                            crate::c71_ea_lpn::cggm_h(
                                self.stream.nonce,
                                block as u64,
                                level as u32,
                                position,
                                node,
                            )
                        }
                    },
                    |term, value| {
                        let words = output[term.row];
                        let sum = Fp3Words(words).fp3() + value.mul_base(term.coefficient);
                        output[term.row] = Fp3Words::from_fp3(sum).0;
                    },
                )
                .map_err(|_| Error::Rejected)?;
                add_work(&mut work, tree_work);
                work.fp3_subtractions += 1;
            }
            work.fp3_by_fp_multiplications += terms.len() as u64;
            work.fp3_additions += terms.len() as u64;
            add_work(&mut self.work, work);
            Ok(output)
        })();
        if result.is_err() {
            self.stream.next = self.stream.limit;
            self.delta.zeroize();
            self.roots.zeroize();
        }
        result
    }

    pub(super) fn heap_bytes(&self) -> usize {
        48 * self.roots.capacity()
    }
}

impl Receiver {
    pub(super) fn new(accepted: Accepted<ReceiverPending>, weight: usize) -> Result<Self, Error> {
        let (pending, binding) = accepted.into_parts();
        let frozen = &pending.guard.frozen;
        let stream = Stream::new(pending.nonce, binding, frozen.blocks, frozen.height, weight)?;
        let mut beta = Zeroizing::new(Vec::with_capacity(frozen.blocks));
        let mut prefix_tags = Zeroizing::new(Vec::with_capacity(frozen.blocks));
        let (mut beta_sum, mut tag_sum) = (Fp::ZERO, Fp3::ZERO);
        for block in 0..frozen.blocks {
            beta_sum += Fp::new(pending.guard.seed.values[block * (frozen.height + 4)])
                + Fp::new(frozen.corrections[block * (frozen.height + 1)]);
            beta.push(beta_sum.value());
            for word in &pending.keys[block * (frozen.height + 1)..][..frozen.height + 1] {
                tag_sum += word.fp3();
            }
            prefix_tags.push(Fp3Words::from_fp3(tag_sum));
        }
        Ok(Self {
            stream,
            alpha: pending.alpha,
            beta,
            keys: pending.keys,
            prefix_tags,
            binding,
            work: Work {
                fp3_additions: (frozen.blocks * (frozen.height + 1)) as u64,
                ..Work::default()
            },
            base_mul_add_pairs: 0,
        })
    }

    pub(super) fn next_row(&mut self) -> Result<[u64; 4], Error> {
        let result = (|| {
            let (terms, mut work) = self.stream.terms()?;
            let (mut value, mut tag) = (Fp::ZERO, Fp3::ZERO);
            let mut on_path = [Fp3::ZERO; 20];
            for term in terms {
                let block = (term.index >> self.stream.height) as usize;
                let omega = term.index & ((1 << self.stream.height) - 1);
                let words =
                    &self.keys[block * (self.stream.height + 1)..][..self.stream.height + 1];
                let (point_tag, point_work) = punc_acc_borrowed(
                    self.stream.nonce,
                    block as u64,
                    omega,
                    self.stream.height,
                    self.alpha[block],
                    words[self.stream.height].fp3(),
                    |level| words[level].fp3(),
                    &mut on_path[..self.stream.height + 1],
                )
                .map_err(|_| Error::Rejected)?;
                add_work(&mut work, point_work);
                let noise = if omega >= self.alpha[block] {
                    Fp::new(self.beta[block])
                } else if block > 0 {
                    Fp::new(self.beta[block - 1])
                } else {
                    Fp::ZERO
                };
                value += term.coefficient * noise;
                self.base_mul_add_pairs += 1;
                let prefix = if block == 0 { Fp3::ZERO } else { self.prefix_tags[block - 1].fp3() };
                tag += (point_tag + prefix).mul_base(term.coefficient);
                work.fp3_by_fp_multiplications += 1;
                work.fp3_additions += 2;
            }
            add_work(&mut self.work, work);
            Ok([value.value(), tag.c0.value(), tag.c1.value(), tag.c2.value()])
        })();
        if result.is_err() {
            self.stream.next = self.stream.limit;
            self.alpha.zeroize();
            self.beta.zeroize();
            self.keys.zeroize();
            self.prefix_tags.zeroize();
        }
        result
    }

    pub(super) fn heap_bytes(&self) -> usize {
        8 * (self.alpha.capacity() + self.beta.capacity())
            + 24 * (self.keys.capacity() + self.prefix_tags.capacity())
    }

    pub(super) fn next_batch(&mut self, count: usize) -> Result<Zeroizing<Vec<[u64; 4]>>, Error> {
        let result = (|| {
            let (terms, mut work) = self.stream.batch_terms(count)?;
            let mut output = Zeroizing::new(vec![[0; 4]; count]);
            let mut remaining = terms.as_slice();
            while let Some(first) = remaining.first() {
                let block = (first.index >> self.stream.height) as usize;
                let boundary = remaining.partition_point(|term| {
                    work.public_index_comparisons += 1;
                    term.index >> self.stream.height == block as u64
                });
                let (queries, rest) = remaining.split_at(boundary);
                remaining = rest;
                let height = self.stream.height;
                let words = &self.keys[block * (height + 1)..][..height + 1];
                let mut on_path = [Fp3::ZERO; 20];
                on_path[height] = words[height].fp3();
                for level in (0..height).rev() {
                    on_path[level] = on_path[level + 1] + words[level].fp3();
                }
                work.fp3_additions += height as u64;
                let prefix = if block == 0 { Fp3::ZERO } else { self.prefix_tags[block - 1].fp3() };
                let alpha = self.alpha[block];
                let tree_work = trie::visit(
                    height,
                    queries,
                    on_path[0],
                    prefix,
                    |level, position, node| {
                        if position == alpha >> (height - level) {
                            let left = if (alpha >> (height - level - 1)) & 1 == 0 {
                                on_path[level + 1]
                            } else {
                                words[level].fp3()
                            };
                            Ok((left, Work::default()))
                        } else {
                            crate::c71_ea_lpn::cggm_h(
                                self.stream.nonce,
                                block as u64,
                                level as u32,
                                position,
                                node,
                            )
                        }
                    },
                    |term, tag| {
                        let omega = term.index & ((1 << height) - 1);
                        let beta = if omega >= alpha {
                            self.beta[block]
                        } else if block > 0 {
                            self.beta[block - 1]
                        } else {
                            0
                        };
                        let words = output[term.row];
                        let value = Fp::new(words[0]) + Fp::new(beta) * term.coefficient;
                        let tag = Fp3Words([words[1], words[2], words[3]]).fp3()
                            + tag.mul_base(term.coefficient);
                        output[term.row] =
                            [value.value(), tag.c0.value(), tag.c1.value(), tag.c2.value()];
                    },
                )
                .map_err(|_| Error::Rejected)?;
                add_work(&mut work, tree_work);
            }
            work.fp3_by_fp_multiplications += terms.len() as u64;
            work.fp3_additions += terms.len() as u64;
            self.base_mul_add_pairs += terms.len() as u64;
            add_work(&mut self.work, work);
            Ok(output)
        })();
        if result.is_err() {
            self.stream.next = self.stream.limit;
            self.alpha.zeroize();
            self.beta.zeroize();
            self.keys.zeroize();
            self.prefix_tags.zeroize();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_seed6_batch_terms_preserve_global_rows_and_fixed_capacity() {
        let mut stream = Stream::new([1; 32], [0x61; 32], 675, 19, 11).unwrap();
        let first = stream.terms().unwrap().0;
        assert_eq!(first, public_ea_row([0x61; 32], 0, 675 << 19, 11).unwrap().0);
        let (terms, work) = stream.batch_terms(BATCH).unwrap();
        assert_eq!(terms.len(), BATCH * 11);
        assert_eq!(terms.capacity(), BATCH * 11);
        assert_eq!(size_of::<trie::Term>(), 24);
        assert_eq!(work.shake_calls, (2 * BATCH * 11) as u64);
        assert!(terms.windows(2).all(|pair| pair[0].index <= pair[1].index));
        for row in [0, 1, BATCH - 1] {
            let expected = public_ea_row([0x61; 32], row as u64 + 1, 675 << 19, 11).unwrap().0;
            let actual: Vec<_> = terms.iter().filter(|term| term.row == row).collect();
            assert_eq!(actual.len(), 11);
            for term in actual {
                assert!(expected.iter().any(
                    |other| other.index == term.index && other.coefficient == term.coefficient
                ));
            }
        }
        assert_eq!(stream.next, BATCH as u64 + 1);
        for count in [0, BATCH + 1] {
            assert!(stream.batch_terms(count).is_err());
        }
        println!("C71_SEED6_BATCH_TERMS rows={BATCH} terms={} native_term_bytes=24 heap_capacity_bytes={}", terms.len(), terms.capacity() * size_of::<trie::Term>());
    }

    #[test]
    fn c71_seed6_expansion_stream_shape_capacity_and_sampler_stop() {
        for (blocks, height, weight) in [
            (0, 4, 2),
            (676, 4, 2),
            (1, 0, 2),
            (1, 20, 2),
            (1, 2, 2),
            (1, 4, 0),
            (1, 4, 12),
            (1, 3, 9),
        ] {
            assert!(Stream::new([1; 32], [2; 32], blocks, height, weight).is_err());
        }
        assert!(Stream::new([0; 32], [2; 32], 1, 4, 2).is_err());
        assert!(Stream::new([1; 32], [0; 32], 1, 4, 2).is_err());
        let mut stream = Stream::new([1; 32], [0x61; 32], 1, 4, 2).unwrap();
        for row in 0..3 {
            let (terms, _) = stream.terms().unwrap();
            assert_eq!(terms, public_ea_row([0x61; 32], row, 16, 2).unwrap().0);
        }
        assert!(stream.terms().is_err());
        assert!(stream.terms().is_err());
        let mut sampler_failed = false;
        for seed in 1..=32 {
            let mut stream = Stream::new([1; 32], [seed; 32], 1, 3, 8).unwrap();
            if stream.terms().is_err() {
                sampler_failed = true;
                assert_eq!(stream.next, stream.limit);
                assert!(stream.terms().is_err());
                break;
            }
        }
        assert!(sampler_failed);
        println!("C71_SEED6_EXPANSION monotone_rows=true capacity_stop=true sampler_stop=true");
    }
}

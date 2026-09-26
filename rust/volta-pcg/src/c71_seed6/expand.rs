//! Reference expansion after F_EQ acceptance, with one monotone row cursor.
//! The public EA seed is derived from verified F_EQ openings. Batch trie,
//! global transcript/burn remain open; no dense pool is materialized here.
use super::{Error, ReceiverPending, SenderPending};
use crate::c71_ea_lpn::{acc, add_work, public_ea_row, punc_acc_borrowed, EaTerm, Work};
use crate::c71_seed6::{equality::Accepted, Fp3Words};
use volta_field::{Fp, Fp3};
use zeroize::{Zeroize, Zeroizing};

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
}

#[cfg(test)]
mod tests {
    use super::*;

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

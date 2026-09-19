//! Bounded end-to-end sourcewise WHIR refinement against the native transcript.
use super::*;
use super::{
    replay_tree::Tree,
    sourcewise::{Getter, State},
};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::{dense::DenseMatrix, extension::FlatMatrixView, Matrix};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use p3_whir_c61::pcs::{
    proof::{QueryOpenings, SharedProofOpening},
    zk::{ZkWhirInitialMessage, ZkWhirOracleCommitter, ZkWhirReplayHandle},
};
use std::sync::Arc;
fn limbs(x: &E) -> &[Goldilocks] {
    <E as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(x)
}
enum Pads {
    Base(Arc<[Goldilocks]>),
    Extension(Vec<E>),
}
impl Pads {
    fn len(&self) -> usize {
        match self {
            Self::Base(v) => v.len(),
            Self::Extension(v) => v.len(),
        }
    }
    fn get(&self, i: usize) -> E {
        match self {
            Self::Base(v) => E::from(v[i]),
            Self::Extension(v) => v[i],
        }
    }
}
struct Code {
    get: Getter,
    len: usize,
    width: usize,
    height: usize,
    pads: Pads,
}
impl Code {
    fn base(&self) -> bool {
        matches!(self.pads, Pads::Base(_))
    }
    fn columns(&self) -> usize {
        self.width * if self.base() { 1 } else { 3 }
    }
    fn coefficient(&self, b: usize, j: usize) -> E {
        let n = self.len / self.width;
        let pad = self.pads.len() / self.width;
        if j < n {
            (self.get)(b * n + j)
        } else {
            assert!(j < n + pad);
            self.pads.get(b * pad + j - n)
        }
    }
    fn coset(&self, c: usize, rows: usize) -> Result<Vec<u64>, String> {
        let z = Goldilocks::two_adic_generator(self.height.ilog2() as usize).exp_u64(c as u64);
        let mut values = vec![E::ZERO; rows * self.width];
        for b in 0..self.width {
            let mut power = Goldilocks::ONE;
            for j in 0..(self.len + self.pads.len()) / self.width {
                values[(j % rows) * self.width + b] += self.coefficient(b, j) * power;
                power *= z;
            }
        }
        let encoded = Radix2DFTSmallBatch::<Goldilocks>::default()
            .dft_algebra_batch(DenseMatrix::new(values, self.width))
            .to_row_major_matrix();
        let mut cells = vec![0; rows * self.columns().max(4)];
        for j in 0..rows {
            for b in 0..self.width {
                let x = encoded.values[j * self.width + b];
                if self.base() {
                    assert_eq!(&limbs(&x)[1..], &[Goldilocks::ZERO; 2]);
                    cells[b * rows + j] = limbs(&x)[0].as_canonical_u64();
                } else {
                    for (k, v) in limbs(&x).iter().enumerate() {
                        cells[(3 * b + k) * rows + j] = v.as_canonical_u64();
                    }
                }
            }
        }
        Ok(cells)
    }
    fn rows(&self, indices: &[usize]) -> Result<Vec<Vec<Goldilocks>>, String> {
        if indices.iter().any(|&i| i >= self.height) {
            return Err("code query outside domain".into());
        }
        // ponytail: batched Horner is bounded correctness evidence; the canonical
        // one-pass schedule uses the independently checked remainder algorithm.
        let root = Goldilocks::two_adic_generator(self.height.ilog2() as usize);
        let points: Vec<_> = indices.iter().map(|&i| root.exp_u64(i as u64)).collect();
        let mut values = vec![E::ZERO; indices.len() * self.width];
        for b in 0..self.width {
            for j in (0..(self.len + self.pads.len()) / self.width).rev() {
                let coefficient = self.coefficient(b, j);
                for (r, &x) in points.iter().enumerate() {
                    let v = &mut values[r * self.width + b];
                    *v = *v * x + coefficient;
                }
            }
        }
        Ok(values
            .chunks_exact(self.width)
            .map(|row| {
                let mut output = Vec::with_capacity(self.columns());
                for v in row {
                    if self.base() {
                        output.push(limbs(v)[0]);
                    } else {
                        output.extend_from_slice(limbs(v));
                    }
                }
                output
            })
            .collect())
    }
    fn commit(
        self,
        mmcs: &HidingMmcs,
    ) -> Result<(replay_tree::Commitment, ZkWhirReplayHandle), String> {
        let base = self.base();
        let code = Arc::new(self);
        let rowcode = code.clone();
        let rows = 256.min(code.height);
        let (root, tree) = Tree::commit(
            mmcs,
            code.height,
            code.columns(),
            rows,
            (code.height / rows).max(16),
            |c| code.coset(c, rows),
            Arc::new(move |indices| rowcode.rows(indices)),
        )?;
        Ok((root, ZkWhirReplayHandle::new(Oracle { tree, base })))
    }
}
struct Oracle {
    tree: Tree,
    base: bool,
}
struct Backend<'a> {
    extension: &'a HidingMmcs,
    source: Getter,
    first: usize,
}
impl<'a> ZkWhirOracleCommitter<Goldilocks, E, &'a HidingMmcs> for Backend<'a> {
    type Error = String;
    type SumcheckState = State;
    fn initialize_sumcheck(
        &self,
        message: ZkWhirInitialMessage<'_, Goldilocks>,
        claims: &[(Point<E>, E)],
        coefficients: &[E],
        target: E,
    ) -> Result<State, String> {
        if claims.len() != 1
            || coefficients != [E::ONE]
            || message.len() != 1 << claims[0].0.num_variables()
        {
            return Err("bounded singleton sourcewise claim".into());
        }
        State::new(self.source.clone(), claims[0].0.as_slice(), self.first, target)
    }
    fn commit_initial(
        &self,
        _: ZkWhirInitialMessage<'_, Goldilocks>,
        _: &[Goldilocks],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<DenseMatrix<Goldilocks>>,
        ),
        String,
    > {
        Err("dense initial commit forbidden".into())
    }
    fn commit_extension(
        &self,
        _: &[E],
        _: &[E],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<
                FlatMatrixView<Goldilocks, E, DenseMatrix<E>>,
            >,
        ),
        String,
    > {
        Err("dense extension commit forbidden".into())
    }
    fn commit_extension_replay_from_sumcheck(
        &self,
        state: &State,
        randomness: &[E],
        folding: usize,
        height: usize,
    ) -> Result<Option<(replay_tree::Commitment, ZkWhirReplayHandle)>, String> {
        Code {
            get: state.getter(),
            len: 1 << state.num_variables(),
            width: 1 << folding,
            height,
            pads: Pads::Extension(randomness.to_vec()),
        }
        .commit(self.extension)
        .map(Some)
    }
    fn evaluate_padded_ood_from_sumcheck(
        &self,
        state: &State,
        point: E,
        suffix: &[E],
    ) -> Result<Option<E>, String> {
        let get = state.getter();
        let mut v = suffix.iter().rev().fold(E::ZERO, |v, &x| v * point + x);
        for i in (0..1 << state.num_variables()).rev() {
            v = v * point + get(i);
        }
        Ok(Some(v))
    }
    fn accumulate_round_claim_from_sumcheck(
        &self,
        state: &mut State,
        domain: usize,
        indices: &[usize],
        points: &[E],
        ood: &[E],
        queries: &[E],
    ) -> Result<bool, String> {
        let root = Goldilocks::two_adic_generator(domain.ilog2() as usize);
        let mut terms: Vec<_> = points.iter().copied().zip(ood.iter().copied()).collect();
        terms.extend(
            indices.iter().zip(queries).map(|(&i, &c)| (E::from(root.exp_u64(i as u64)), c)),
        );
        state.add_powers(&terms)?;
        Ok(true)
    }
    fn open_replay(
        &self,
        handle: &ZkWhirReplayHandle,
        indices: &[usize],
        randomness: &Point<E>,
    ) -> Result<Option<(QueryOpenings<Goldilocks, E, replay_tree::MultiProof>, Vec<E>)>, String>
    {
        let oracle = handle.downcast_ref::<Oracle>().ok_or("replay handle type")?;
        let (rows, proof) = oracle.tree.open(indices)?;
        let rows: Vec<_> = rows.into_iter().map(|mut v| v.remove(0)).collect();
        if oracle.base {
            let folded = rows.iter().map(|v| Poly::new(v.clone()).eval_base(randomness)).collect();
            Ok(Some((QueryOpenings::Base(SharedProofOpening { rows, proof }), folded)))
        } else {
            let rows: Vec<Vec<E>> = rows
                .iter()
                .map(|v| v.chunks_exact(3).map(|c| E::new(c.try_into().unwrap())).collect())
                .collect();
            let folded = rows
                .iter()
                .map(|v| Poly::new(v.clone()).eval_ext::<Goldilocks>(randomness))
                .collect();
            Ok(Some((QueryOpenings::Extension(SharedProofOpening { rows, proof }), folded)))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_010::RngExt;
    #[test]
    fn c71_b12_full_sourcewise_chain_matches_native_bytes() {
        census::start().unwrap();
        let config = config(10).unwrap();
        let dft = Radix2DFTSmallBatch::default();
        let native = mmcs([73; 32]);
        let reference = HidingWhirProver::new(&config, &dft, &native);
        let source: Getter = Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
        let witness = Poly::new((0..1024).map(|i| limbs(&source(i))[0]).collect());
        let point = Point::new(
            (0..10)
                .map(|i| E::new([Goldilocks::new(i + 3), Goldilocks::new(7), Goldilocks::new(11)]))
                .collect(),
        );
        let value = witness.eval_base(&point);
        let claims = [(point.clone(), value)];
        let mut rng = PrivateRng::from_seed([91; 32]);
        let mut fs = Fs::new(b"sourcewise refinement", request_limit(&config));
        let (root, data) = reference.commit(witness, &mut fs, &mut rng);
        let result = reference.prove_claimless(data, &claims, E::ZERO, &mut fs, &mut rng);
        census::mark("sourcewise_initial_commit").unwrap();
        let base = mmcs([73; 32]);
        let extension = base.clone();
        let base_ref = &base;
        let engine = HidingWhirProver {
            config: &config,
            dft: &dft,
            mmcs: &base_ref,
            extension_mmcs: ExtensionMmcs::new(&extension),
        };
        let mut replay_rng = PrivateRng::from_seed([91; 32]);
        let mut replay_fs = Fs::new(b"sourcewise refinement", request_limit(&config));
        let first = config.round_folding_factor(0);
        let pads: Arc<[Goldilocks]> =
            (0..config.oracle_randomness[0] << first).map(|_| replay_rng.random()).collect();
        let height = (1024 >> first) << config.starting_log_inv_rate;
        let (replay_root, handle) = Code {
            get: source.clone(),
            len: 1024,
            width: 1 << first,
            height,
            pads: Pads::Base(pads.clone()),
        }
        .commit(&base)
        .unwrap();
        assert_eq!(root, replay_root);
        replay_fs.observe(replay_root.clone());
        census::mark("sourcewise_open_all_rounds").unwrap();
        let backend = Backend { extension: &extension, source, first };
        let output = engine
            .prove_claimless_replay_with_oracle(
                1024,
                &pads,
                handle,
                &claims,
                E::ZERO,
                &backend,
                &mut replay_fs,
                &mut replay_rng,
            )
            .unwrap();
        census::mark("codec_and_native_verifier").unwrap();
        assert_eq!(
            serde_json::to_vec(&result.proof).unwrap(),
            serde_json::to_vec(&output.proof).unwrap()
        );
        let canonical = |value| {
            let matrix = MatrixProof {
                rounds: vec![[Fp3::ZERO; 4]; 10],
                terminal: [Fp3::ZERO; 2],
                pcs: serde_json::from_value(value).unwrap(),
                close_tag: Fp3::ZERO,
            };
            codec::encode_linear(Domain::Flat(10), &matrix).unwrap()
        };
        let native_bytes = canonical(serde_json::to_value(&result.proof).unwrap());
        assert_eq!(native_bytes, canonical(serde_json::to_value(&output.proof).unwrap()));
        eprintln!("sourcewise D10 canonical_bytes={}", native_bytes.len());
        assert_eq!(fs.digest(), replay_fs.digest());
        assert_eq!(rng.position(), replay_rng.position());
        assert_eq!(result.target, output.target);
        assert_eq!(result.base_case, output.base_case);
        let mut verifier_fs = Fs::new(b"sourcewise refinement", request_limit(&config));
        verifier_fs.observe(root.clone());
        let checked = HidingWhirVerifier::new(&config, &base_ref)
            .verify_claimless(&output.proof, &root, &[point], &mut verifier_fs)
            .unwrap();
        assert_eq!(checked.target, output.target);
        assert_eq!(checked.base_case, output.base_case);
        assert_eq!(verifier_fs.digest(), fs.digest());
        eprintln!("sourcewise_allocator={}", census::finish().unwrap());
    }
}

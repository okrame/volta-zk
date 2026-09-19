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
    base: &'a ObservedMmcs,
    extension: &'a ObservedMmcs,
    source: Getter,
    first: usize,
    retain_first: bool,
}
impl<'a> ZkWhirOracleCommitter<Goldilocks, E, &'a ObservedMmcs> for Backend<'a> {
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
        State::new(
            self.source.clone(),
            claims[0].0.as_slice(),
            self.first,
            target,
            self.retain_first,
        )
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
        .commit(&self.extension.inner)
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
        // The C7.1 wrapper binds original rows/salts/frontier into FS before
        // the next coin, including extension rows in their native base layout.
        let mmcs = if oracle.base { self.base } else { self.extension };
        mmcs.bind(indices, &rows, &proof);
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
pub(in crate::c71_matrix) fn compare_source(
    dimension: usize,
    source: Getter,
    values: Vec<Goldilocks>,
    original: Option<&Model>,
) {
    use rand_010::RngExt;
    assert!((10..=12).contains(&dimension));
    assert_eq!(values.len(), 1 << dimension);
    census::start().unwrap();
    let config = config(dimension).unwrap();
    let dft = Radix2DFTSmallBatch::default();
    let salt_seed = original.map_or([73; 32], |m| m.salt_seed);
    let root_seed = original.map_or([91; 32], |m| m.seed);
    let witness = Poly::new(values);
    let point = Point::new(
        (0..dimension)
            .map(|i| {
                E::new([Goldilocks::new(i as u64 + 3), Goldilocks::new(7), Goldilocks::new(11)])
            })
            .collect(),
    );
    let value = witness.eval_base(&point);
    // Original endpoint fixed before the proof. Ideal MACs here, as in the
    // bounded composed runner; no reauthentication after challenges.
    let delta =
        Fp3::new(volta_field::Fp::new(7), volta_field::Fp::new(11), volta_field::Fp::new(13));
    let terminal_key = Key { k: Fp3::ONE };
    let terminal = Auth { x: from_p3(value), m: terminal_key.k - delta * from_p3(value) };
    let mask_key = Key { k: Fp3::ONE + Fp3::ONE };
    let mask = Auth { x: Fp3::ONE, m: mask_key.k - delta };
    let claims = [(point.clone(), value)];
    let mut fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    fs.set_phase(0x200);
    let root_mmcs = ObservedMmcs::new(fs.clone(), salt_seed);
    let root_prover = HidingWhirProver::new(&config, &dft, &root_mmcs);
    let mut root_rng = PrivateRng::from_seed(root_seed);
    let (root, data) = root_prover.commit(witness, &mut fs, &mut root_rng);
    if let Some(original) = original {
        assert_eq!(root, original.root);
    }
    // Actual C7.1 discipline: fresh proof coins/MMCS, independent of root replay.
    let proof_mmcs = ObservedMmcs::new(fs.clone(), [83; 32]);
    let reference = HidingWhirProver::new(&config, &dft, &proof_mmcs);
    let mut rng = PrivateRng::from_seed([101; 32]);
    let result = reference.prove_claimless(data, &claims, to_p3(mask.x), &mut fs, &mut rng);

    census::mark("sourcewise_initial_commit").unwrap();
    let mut replay_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    replay_fs.set_phase(0x200);
    let original_mmcs = ObservedMmcs::new(replay_fs.clone(), salt_seed);
    let _original_extension = original_mmcs.clone(); // the native initial-construction fork
    let mut initial_rng = PrivateRng::from_seed(root_seed);
    let first = config.round_folding_factor(0);
    let pads: Arc<[Goldilocks]> =
        (0..config.oracle_randomness[0] << first).map(|_| initial_rng.random()).collect();
    let height = ((1 << dimension) >> first) << config.starting_log_inv_rate;
    let (replay_root, handle) = Code {
        get: source.clone(),
        len: 1 << dimension,
        width: 1 << first,
        height,
        pads: Pads::Base(pads.clone()),
    }
    .commit(&original_mmcs.inner)
    .unwrap();
    assert_eq!(root, replay_root);
    assert_eq!(root_rng.position(), initial_rng.position());
    replay_fs.observe(replay_root.clone());
    let base = ObservedMmcs::new(replay_fs.clone(), [83; 32]);
    let extension = base.clone();
    let base_ref = &base;
    let engine = HidingWhirProver {
        config: &config,
        dft: &dft,
        mmcs: &base_ref,
        extension_mmcs: ExtensionMmcs::new(&extension),
    };
    let mut replay_rng = PrivateRng::from_seed([101; 32]);
    census::mark("sourcewise_open_all_rounds").unwrap();
    let backend = Backend {
        base: &base,
        extension: &extension,
        source,
        first,
        retain_first: original.is_some(),
    };
    let output = engine
        .prove_claimless_replay_with_oracle(
            1 << dimension,
            &pads,
            handle,
            &claims,
            to_p3(mask.x),
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
    let close_tag =
        mask.m - from_p3(output.base_case.gamma * output.target.coefficient) * terminal.m;
    assert_eq!(
        close_tag,
        mask.m - from_p3(result.base_case.gamma * result.target.coefficient) * terminal.m
    );
    let canonical = |value| {
        let matrix = MatrixProof {
            rounds: vec![[Fp3::ZERO; 4]; dimension],
            terminal: [Fp3::ZERO; 2],
            pcs: serde_json::from_value(value).unwrap(),
            close_tag,
        };
        codec::encode_linear(Domain::Flat(dimension), &matrix).unwrap()
    };
    let bytes = canonical(serde_json::to_value(&result.proof).unwrap());
    assert_eq!(bytes, canonical(serde_json::to_value(&output.proof).unwrap()));
    eprintln!("sourcewise observed D{dimension} canonical_bytes={}", bytes.len());
    assert_eq!(fs.digest(), replay_fs.digest());
    assert_eq!(rng.position(), replay_rng.position());
    assert_eq!(result.target, output.target);
    assert_eq!(result.base_case, output.base_case);
    record_values(&mut fs, 0x12, &[close_tag]);
    record_values(&mut replay_fs, 0x12, &[close_tag]);
    let owned_proof: ZkWhirProof<Goldilocks, E, ObservedMmcs> =
        serde_json::from_value(serde_json::to_value(&output.proof).unwrap()).unwrap();
    let mut verifier_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    verify_pcs(
        &config,
        &root,
        point.clone(),
        &owned_proof,
        close_tag,
        terminal_key,
        mask_key,
        delta,
        &mut verifier_fs,
    )
    .unwrap();
    assert_eq!(verifier_fs.digest(), fs.digest());
    // A coherently encoded proof cannot be closed on a different endpoint MAC.
    let mut wrong_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    assert!(verify_pcs(
        &config,
        &root,
        point,
        &owned_proof,
        close_tag,
        Key { k: terminal_key.k + Fp3::ONE },
        mask_key,
        delta,
        &mut wrong_fs
    )
    .is_err());
    eprintln!("sourcewise_allocator={}", census::finish().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_b12_full_sourcewise_chain_matches_native_bytes() {
        let source: Getter = Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
        let values = (0..1024).map(|i| limbs(&source(i))[0]).collect();
        compare_source(10, source, values, None);
    }
}

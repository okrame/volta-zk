//! Parameter experiment only: no selected profile or canonical prover change.
use super::*;
use p3_dft::TwoAdicSubgroupDft;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

#[derive(Clone, Default)]
struct CountDft {
    inner: Radix2DFTSmallBatch<Goldilocks>,
    // Per-call dimensions only, outside the arithmetic kernel; not timing.
    calls: std::sync::Arc<std::sync::Mutex<Vec<(usize, usize)>>>,
}

impl TwoAdicSubgroupDft<Goldilocks> for CountDft {
    type Evaluations =
        <Radix2DFTSmallBatch<Goldilocks> as TwoAdicSubgroupDft<Goldilocks>>::Evaluations;

    fn dft_batch(&self, matrix: RowMajorMatrix<Goldilocks>) -> Self::Evaluations {
        self.calls.lock().unwrap().push((matrix.height(), matrix.width()));
        self.inner.dft_batch(matrix)
    }
}

fn candidate(h: usize, exposures: usize) -> ZkWhirConfig<E, Goldilocks, Fs> {
    parameters(h, exposures, if h <= 14 { 4 } else { 6 })
}

fn parameters(h: usize, exposures: usize, first: usize) -> ZkWhirConfig<E, Goldilocks, Fs> {
    let queries = 456;
    let ell = exposures * queries + 1;
    let strategy = FoldingFactor::ConstantFromSecondRound(first, 4);
    let folds = strategy.compute_folding_schedule(h).unwrap();
    let mut remaining = h;
    let rates: Vec<_> = folds
        .iter()
        .enumerate()
        .map(|(i, &f)| {
            remaining -= f;
            let pad = if i == 0 { exposures * queries } else { queries };
            (4 * ((1usize << remaining) + pad)).next_power_of_two().ilog2() as usize - remaining
        })
        .collect();
    let mut c = ZkWhirConfig::new(
        h,
        ProtocolParameters {
            security_level: 128,
            pow_bits: 0,
            starting_log_inv_rate: rates[0],
            round_log_inv_rates: rates[1..].to_vec(),
            folding_factor: strategy,
            soundness_type: SecurityAssumption::JohnsonBound,
        },
        ZkParameters { ell_zk: ell, mask_log_inv_rate: 2 },
    )
    .unwrap();
    c.mask_queries = queries;
    c.oracle_randomness.fill(queries);
    c.oracle_randomness[0] = exposures * queries;
    c.sumcheck_mask = MaskCodeShape::new(ell, queries, 2);
    c.switch_masks.fill(c.sumcheck_mask);
    for round in &mut c.inner.round_parameters {
        round.num_queries = queries;
        round.ood_samples = 1;
    }
    c.inner.final_queries = queries;
    c
}

#[test]
fn c71_pcs_tuning_valid_original_mac_and_codec() {
    for (h, exposures, first) in [(12, 3, 4), (12, 2, 4), (12, 1, 4), (13, 2, 5)] {
        for tuned in [false, true] {
            let c = if tuned { parameters(h, exposures, first) } else { b12::config(h).unwrap() };
            let mut model = Model {
                domain: Domain::Flat(h),
                weights: (0..1 << h).map(|i| (i % 31) - 15).collect(),
                seed: [71; 32],
                salt_seed: [72; 32],
                root: C61Commitment::new(vec![[0; 32]]),
            };
            let mmcs = matrix_mmcs(model.salt_seed);
            let dft = Radix2DFTSmallBatch::default();
            let prover = HidingWhirProver::new(&c, &dft, &mmcs);
            let mut setup = Fs::new(b"tuning setup independent of Delta", 0);
            model.root = prover
                .commit(model.polynomial(), &mut setup, &mut MatrixRng::from_seed(model.seed))
                .0;
            // Distinct fresh points/tags per exposure; only the installed root repeats.
            for slot in 0..exposures {
                let point: Vec<_> = (0..h).map(|i| signed((i + 3 + slot) as i64)).collect();
                let value = model
                    .weights
                    .iter()
                    .zip(eq(&point))
                    .fold(Fp3::ZERO, |s, (&w, e)| s + signed(i64::from(w)) * e);
                let terminal = Auth::new(value, signed(21 + slot as i64));
                let mask = Auth::new(signed(43 + slot as i64), signed(51 + slot as i64));
                let delta = signed(19);
                let key = |a: Auth| Key::new(a.m + delta * a.x);
                let start = || {
                    let mut fs = Fs::new(b"C71 PCS tuning experiment only", request_limit(&c));
                    fs.record(0x70, &gamma(&c));
                    fs.record(0x71, &(slot as u64).to_le_bytes());
                    fs
                };
                let mut fs = start();
                let p = Point::new(point.iter().copied().map(to_p3).collect());
                let (pcs, close_tag) =
                    prove_pcs(&model, &c, p.clone(), terminal, mask, &mut fs).unwrap();
                // Only PCS is proved here. Two zero terminal words are codec scaffolding.
                let proof =
                    MatrixProof { rounds: vec![], terminal: [Fp3::ZERO; 2], pcs, close_tag };
                let bytes = encode_body(&c, 0, &proof, C61Writer::default()).unwrap();
                let decoded = decode_body(&c, 0, C61Reader::new(&bytes)).unwrap();
                let mut vf = start();
                verify_pcs(
                    &c,
                    &model.root,
                    p.clone(),
                    &decoded.pcs,
                    decoded.close_tag,
                    key(terminal),
                    key(mask),
                    delta,
                    &mut vf,
                )
                .unwrap();
                assert_eq!(fs.digest(), vf.digest());
                assert!(verify_pcs(
                    &c,
                    &model.root,
                    p,
                    &decoded.pcs,
                    decoded.close_tag,
                    key(terminal.add(Auth::new(Fp3::ONE, Fp3::ZERO))),
                    key(mask),
                    delta,
                    &mut start()
                )
                .is_err());
                assert!(decode_body(&c, 0, C61Reader::new(&bytes[..bytes.len() - 1])).is_err());
                eprintln!("PCS tuning valid D{h} exposures={exposures} tuned={tuned} slot={slot} pcs_bytes={}", bytes.len()-48);
            }
        }
    }
}

#[test]
fn c71_pcs_tuning_canonical_geometry() {
    for (h, exposures, first, fixed, upper) in [
        (35, 3, 6, 5_157_568, 7_932_608),
        (34, 2, 6, 4_434_784, 7_136_864),
        (35, 1, 7, 4_000_792, 6_323_480),
        (36, 2, 8, 5_288_656, 7_990_736),
    ] {
        let c = parameters(h, exposures, first);
        assert!(c.mask_groups().iter().all(|g| g.shape == c.sumcheck_mask));
        for (i, r) in
            c.round_parameters.iter().chain(std::iter::once(&c.final_round_config())).enumerate()
        {
            let domain = r.domain_size >> r.folding_factor;
            let k = (1usize << r.num_variables) + c.oracle_randomness[i];
            assert!(3 * (domain / 4) < domain - k + 1);
            assert!(domain <= 1usize << 32);
            assert!(c.zk.ell_zk > c.oracle_randomness[i]);
        }
        eprintln!(
            "PCS tuning D{h} folds={:?} ell={} mask_domain={} profile_bytes={}",
            (0..=c.n_rounds()).map(|i| c.round_folding_factor(i)).collect::<Vec<_>>(),
            c.zk.ell_zk,
            c.sumcheck_mask.domain_size,
            gamma(&c).len()
        );
        let mut fixture = decode_body(&c, h, C61Reader::new(&vec![0; fixed])).unwrap();
        assert_eq!(encode_body(&c, h, &fixture, C61Writer::default()).unwrap().len(), fixed);
        super::tests::set_frontiers(&c, &mut fixture, usize::MAX);
        let encoded = encode_body(&c, h, &fixture, C61Writer::default()).unwrap();
        assert_eq!(encoded.len(), upper);
        let restored = decode_body(&c, h, C61Reader::new(&encoded)).unwrap();
        assert_eq!(encode_body(&c, h, &restored, C61Writer::default()).unwrap(), encoded);
        eprintln!("PCS tuning synthetic D{h} fixed={fixed} upper={upper}");
    }
}

#[test]
fn c71_pcs_retained_commit_data_preserves_wire_and_removes_rebuild() {
    use p3_challenger::CanObserve;
    for (h, tuned) in [(12, false), (12, true), (10, true)] {
        let exposures = if tuned { 2 } else { 3 };
        let c = if tuned { candidate(h, exposures) } else { b12::config(h).unwrap() };
        let dft = CountDft::default();
        let values: Vec<_> = (0..1 << h).map(|i| Goldilocks::new((i % 31) as u64)).collect();
        let mut setup = Fs::new(b"retained setup independent of Delta", 0);
        let model_mmcs = ObservedMmcs::new(setup.clone(), [72; 32]);
        let committer = HidingWhirProver::new(&c, &dft, &model_mmcs);
        let (root, retained) = committer.commit(
            Poly::new(values.clone()),
            &mut setup,
            &mut MatrixRng::from_seed([71; 32]),
        );
        let setup_calls = std::mem::take(&mut *dft.calls.lock().unwrap());
        assert_eq!(setup_calls.len(), 1);
        let message_ptr = retained.message.host().unwrap().as_slice().as_ptr();
        let pad_ptr = retained.randomness.as_ptr();
        let leaves = retained.merkle.c61_spill_leaves();
        let matrix_ptr = leaves[0].left.values.as_ptr();
        let salts_ptr = leaves[0].right.values.as_ptr();
        let digests = retained.merkle.c61_spill_digest_layers();
        let digest_count: usize = digests.iter().map(Vec::len).sum();
        let root_ptr = digests.last().unwrap().as_ptr();
        let retained_payload = 8
            * (values.len()
                + retained.randomness.len()
                + leaves[0].left.values.len()
                + leaves[0].right.values.len())
            + 32 * digest_count;
        let retained_capacity = 8
            * (values.capacity()
                + retained.randomness.capacity()
                + leaves[0].left.values.capacity()
                + leaves[0].right.values.capacity())
            + 32 * digests.iter().map(Vec::capacity).sum::<usize>();
        assert_eq!(digest_count, 2 * setup_calls[0].0 - 1);
        for slot in 0..exposures {
            let point: Vec<_> = (0..h).map(|i| signed((i + 3 + slot) as i64)).collect();
            let terminal = Auth::new(
                values.iter().zip(eq(&point)).fold(Fp3::ZERO, |s, (x, e)| {
                    s + Fp3::from_base(Fp::new(x.as_canonical_u64())) * e
                }),
                signed(21 + slot as i64),
            );
            let mask = Auth::new(signed(43 + slot as i64), signed(51 + slot as i64));
            let claims = [(Point::new(point.into_iter().map(to_p3).collect()), to_p3(terminal.x))];
            let start = || {
                let mut fs = Fs::new(b"C71 retained-data comparison", request_limit(&c));
                fs.record(0x70, &gamma(&c));
                fs.record(0x71, &(slot as u64).to_le_bytes());
                fs.set_phase(0x200);
                fs
            };
            let mut paired = Vec::new();
            let mut traces = Vec::new();
            for cached in [false, true] {
                let mut fs = start();
                let rebuilt = if cached {
                    fs.observe(root.clone()); // same event as commit, with no new root/coins
                    None
                } else {
                    let mmcs = ObservedMmcs::new(fs.clone(), [72; 32]);
                    let (r, data) = HidingWhirProver::new(&c, &dft, &mmcs).commit(
                        Poly::new(values.clone()),
                        &mut fs,
                        &mut MatrixRng::from_seed([71; 32]),
                    );
                    assert_eq!(r, root);
                    Some(data)
                };
                // Fresh per exposure; the two executions compare the SAME random tape.
                let mmcs = ObservedMmcs::new(fs.clone(), [90 + slot as u8; 32]);
                let prover = HidingWhirProver::new(&c, &dft, &mmcs);
                let mut rng = MatrixRng::from_seed([80 + slot as u8; 32]);
                let out = if let Some(data) = rebuilt {
                    prover.prove_claimless(data, &claims, to_p3(mask.x), &mut fs, &mut rng)
                } else {
                    prover.prove_claimless_retained(
                        &retained,
                        &claims,
                        to_p3(mask.x),
                        &mut fs,
                        &mut rng,
                    )
                };
                let close_tag =
                    mask.m - from_p3(out.base_case.gamma * out.target.coefficient) * terminal.m;
                record_values(&mut fs, 0x12, &[close_tag]);
                let proof = MatrixProof {
                    rounds: vec![],
                    terminal: [Fp3::ZERO; 2],
                    pcs: out.proof,
                    close_tag,
                };
                // The C71 codec only admits a cubic final oracle. A no-switch
                // library proof has a base-field final oracle: check its full
                // serde representation and verifier, without widening that codec.
                let encoded = if c.n_rounds() == 0 {
                    assert!(encode_body(&c, 0, &proof, C61Writer::default()).is_err());
                    serde_json::to_vec(&proof.pcs).unwrap()
                } else {
                    encode_body(&c, 0, &proof, C61Writer::default()).unwrap()
                };
                let delta = signed(19);
                let key = |a: Auth| Key::new(a.m + delta * a.x);
                let mut vf = start();
                verify_pcs(
                    &c,
                    &root,
                    claims[0].0.clone(),
                    &proof.pcs,
                    close_tag,
                    key(terminal),
                    key(mask),
                    delta,
                    &mut vf,
                )
                .unwrap();
                assert_eq!(vf.digest(), fs.digest());
                paired.push((encoded, fs.digest()));
                traces.push(std::mem::take(&mut *dft.calls.lock().unwrap()));
            }
            assert_eq!(paired[0], paired[1]);
            assert_eq!(traces[0][0], setup_calls[0]);
            assert_eq!(traces[0][1..], traces[1]);
            assert_eq!(retained.message.host().unwrap().as_slice().as_ptr(), message_ptr);
            assert_eq!(retained.randomness.as_ptr(), pad_ptr);
            assert_eq!(retained.merkle.c61_spill_leaves()[0].left.values.as_ptr(), matrix_ptr);
            assert_eq!(retained.merkle.c61_spill_leaves()[0].right.values.as_ptr(), salts_ptr);
            assert_eq!(
                retained.merkle.c61_spill_digest_layers().last().unwrap().as_ptr(),
                root_ptr
            );
            let native_bytes = (c.n_rounds() != 0).then(|| paired[0].0.len() - 48);
            eprintln!("PCS retained D{h} tuned={tuned} slot={slot} identical_native_pcs_bytes={native_bytes:?} removed_DFT={:?} retained_payload={retained_payload} retained_buffer_capacity={retained_capacity}",
                setup_calls[0]);
        }
    }
}

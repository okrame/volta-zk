//! Parameter experiment only: no selected profile or canonical prover change.
use super::*;

fn candidate(h: usize, exposures: usize) -> ZkWhirConfig<E, Goldilocks, Fs> {
    let queries = 456;
    let ell = exposures * queries + 1;
    let strategy = FoldingFactor::ConstantFromSecondRound(if h <= 14 { 4 } else { 6 }, 4);
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
    let h = 12;
    for exposures in [3, 2] {
        for tuned in [false, true] {
            let c = if tuned { candidate(h, exposures) } else { b12::config(h).unwrap() };
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
    for (h, exposures, fixed, upper) in
        [(35, 3, 5_157_568, 7_932_608), (34, 2, 4_434_784, 7_136_864)]
    {
        let c = candidate(h, exposures);
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

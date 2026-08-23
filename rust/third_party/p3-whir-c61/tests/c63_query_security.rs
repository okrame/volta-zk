use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir_c61::pcs::zk::{ZkParameters, ZkWhirConfig};

type Fp2 = BinomialExtensionField<Goldilocks, 2>;
type Challenger = SerializingChallenger64<Goldilocks, HashChallenger<u8, Blake3, 32>>;

fn params(pow_bits: usize, rates: Vec<usize>, folding: Vec<usize>) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 105,
        pow_bits,
        round_log_inv_rates: rates,
        folding_factor: FoldingFactor::PerRound(folding),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn zk() -> ZkParameters {
    ZkParameters { ell_zk: 16, mask_log_inv_rate: 1 }
}

#[test]
fn c63_d22_and_d19_keep_full_105_bit_query_targets() {
    let cases = [
        (
            22,
            18,
            vec![1, 2, 3, 3, 4, 5, 6, 7],
            vec![1, 2, 2, 2, 2, 2, 2, 2, 2],
            vec![245, 245, 113, 74, 74, 55, 44, 36],
            31,
            257,
        ),
        (
            19,
            17,
            vec![1, 2, 3, 4, 5, 6],
            vec![1, 2, 2, 2, 2, 2, 2],
            vec![245, 245, 113, 74, 55, 44],
            36,
            254,
        ),
    ];

    for (variables, pow_bits, rates, folding, round_queries, final_queries, mask_queries) in cases {
        let config = ZkWhirConfig::<Fp2, Goldilocks, Challenger>::new_with_query_security_level(
            variables,
            params(pow_bits, rates, folding),
            zk(),
            105,
        )
        .unwrap();

        assert_eq!(
            config.round_parameters.iter().map(|round| round.num_queries).collect::<Vec<_>>(),
            round_queries
        );
        assert_eq!(config.final_queries, final_queries);
        assert_eq!(config.mask_queries, mask_queries);
        assert_eq!(config.max_pow_bits(), pow_bits);
    }
}

#[test]
fn legacy_constructor_keeps_the_previous_derived_configuration() {
    let mut params = params(17, vec![1, 2, 3, 3, 4, 5, 6, 7], vec![1, 2, 2, 2, 2, 2, 2, 2, 2]);
    params.security_level = 104;
    let legacy_query_security = params.security_level.saturating_sub(params.pow_bits);

    let legacy = WhirConfig::<Fp2, Goldilocks, Challenger>::new(22, params.clone()).unwrap();
    let explicit = WhirConfig::<Fp2, Goldilocks, Challenger>::new_with_query_security_level(
        22,
        params.clone(),
        legacy_query_security,
    )
    .unwrap();
    assert_eq!(format!("{legacy:?}"), format!("{explicit:?}"));

    let legacy =
        ZkWhirConfig::<Fp2, Goldilocks, Challenger>::new(22, params.clone(), zk()).unwrap();
    let explicit = ZkWhirConfig::<Fp2, Goldilocks, Challenger>::new_with_query_security_level(
        22,
        params,
        zk(),
        legacy_query_security,
    )
    .unwrap();
    assert_eq!(format!("{legacy:?}"), format!("{explicit:?}"));
}

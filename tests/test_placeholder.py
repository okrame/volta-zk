from volta_zk.placeholders import ProverNativeRatio


def test_prover_native_ratio() -> None:
    ratio = ProverNativeRatio(prover_wall_time_s=6.0, native_wall_time_s=2.0)

    assert ratio.rho == 3.0

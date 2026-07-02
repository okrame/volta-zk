"""Placeholder types for the initial VOLTA-ZK scaffold."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ProverNativeRatio:
    """Benchmark ratio used throughout the project."""

    prover_wall_time_s: float
    native_wall_time_s: float

    @property
    def rho(self) -> float:
        if self.native_wall_time_s <= 0:
            raise ValueError("native_wall_time_s must be positive")
        return self.prover_wall_time_s / self.native_wall_time_s

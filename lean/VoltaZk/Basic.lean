/-!
# VOLTA-ZK formalization

Formal target #1 (see `docs/protocol-sketch.md` and `initial-brainstorming.md`):
perfect zero-knowledge of the blind sumcheck `Π_BSC` composed with the batched
zero-opening `Π_ZeroBatch` against a *malicious* designated verifier `V*`, in
the `F_sVOLE`-hybrid model.

Module map:

* `VoltaZk.Mac` — VOLE-style MAC-authenticated values and their linearity.
* `VoltaZk.Otp` — one-time-pad lemma: uniform masks make corrections uniform.
* `VoltaZk.Vole` — corrupted-verifier branch of the ideal `F_sVOLE` and `Π_Auth`.
* `VoltaZk.ZeroBatch` — `Π_ZeroOpen` / `Π_ZeroBatch` and their perfect simulator.
* `VoltaZk.BlindSumcheck` — `Π_BSC` transcripts, malicious `V*`, main ZK theorem.
* `VoltaZk.Ideal` — everything deliberately kept as an assumption (PCG, malicious
  VOLE, PCS, QuickSilver, LogUp, UC composition).
-/

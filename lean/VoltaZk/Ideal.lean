/-!
# Deferred ideal functionalities and assumptions

Everything the first formal target deliberately does **not** prove, kept as
named propositions so that later theorems can take them as explicit
hypotheses. Each maps to an entry of `docs/protocol-sketch.md`
§ "Security Proof Tasks" or to the system design in
`initial-brainstorming.md`.

These are `axiom`s of type `Prop` with *deferred content*: they name an
assumption whose precise formal statement is future work. Nothing in the
proven lemmas of this development may depend on them (checked with
`#print axioms`).

Formerly listed here and since proved: `BlindSumcheckSound` (M3) — see
`VoltaZk.blind_sumcheck_sound` / `VoltaZk.blind_sumcheck_sound_mv`;
`AuthenticatedCacheSound` (M4) — see `VoltaZk.kv_cache_sound` /
`VoltaZk.authenticated_cache_sound` in `VoltaZk/KvCache.lean`; and
`SubfieldCorrection` (M5) — see `VoltaZk.sub_correction_uniform` /
`VoltaZk.sub_zeroOpen_sound` in `VoltaZk/Subfield.lean`.
-/

namespace VoltaZk.Ideal

/-- (Deferred) A Ferret/PCG-style silent-VOLE protocol UC-realizes `F_sVOLE`
against malicious parties, including selective-failure leakage handling.
Here `F_sVOLE` appears only through its corrupted-verifier branch
(`VoltaZk.freshCorr`). -/
axiom FerretRealizesSVOLE : Prop

/-- (Deferred) **Soundness** of the QuickSilver-style degree-`d` product
check `Π_Prod` used to close multiplicative claims, batched into the same
`Π_ZeroBatch` list. The ZK half is proved: `VoltaZk.prod_perfect_sim` in
`VoltaZk/Prod.lean` (M7). -/
axiom QuickSilverProdSound : Prop

/-- (Deferred) Binding and (blinded) ZK of the public multilinear PCS
(Basefold/WHIR) for the weight commitment `C_W`, and soundness of the
windowed multi-point batch opening. -/
axiom WeightPCSBinding : Prop

/-- (Deferred) Soundness of LogUp-GKR (fractional sumcheck) for the fused
non-linearity lookups, composed with the authenticated transcript. -/
axiom LogUpGKRSound : Prop

/-- (Deferred) Full UC composition: `Π_VOLTA` realizes the stateful verifiable
decoding functionality `F_VDec` in the `(F_sVOLE, F_PCS)`-hybrid model. -/
axiom UCComposition : Prop

end VoltaZk.Ideal

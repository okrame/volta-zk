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
`VoltaZk.sub_zeroOpen_sound` in `VoltaZk/Subfield.lean`; and
`QuickSilverProdSound` (M8) — see `VoltaZk.prodBatch_sound` in
`VoltaZk/ProdSound.lean` (ZK half: `VoltaZk.prod_perfect_sim`, M7).
Higher fan-in products reduce to chained degree-2 checks.
-/

namespace VoltaZk.Ideal

/-- (Deferred) A Ferret/PCG-style silent-VOLE protocol UC-realizes `F_sVOLE`
against malicious parties, including selective-failure leakage handling.
Here `F_sVOLE` appears only through its corrupted-verifier branch
(`VoltaZk.freshCorr`). -/
axiom FerretRealizesSVOLE : Prop

/-- (Deferred) Three separate obligations for the implemented Ligero-style
weight PCS: (i) commitment/evaluation binding, (ii) the VOLTA-specific
blinded-ZK composition, and (iii) windowed multi-point batch soundness.
They require separate statements and appropriate citations at discharge;
no single PCS-family citation proves their conjunction. -/
axiom WeightPCSBinding : Prop

/-- (Deferred) Soundness of LogUp-GKR (fractional sumcheck) for the fused
non-linearity lookups, composed with the authenticated transcript. -/
axiom LogUpGKRSound : Prop

/-- (Deferred) Conditional UC composition: `Π_VOLTA` realizes the stateful
verifiable-decoding functionality `F_VDec` in the `(F_sVOLE, F_PCS)`-hybrid
model only after separate realizations of both ideal functionalities are
supplied. The cited Ligero/BaseFold-family PCS results do not themselves
establish a UC realization of `F_PCS`, and ROM extractability may not be
silently substituted for that premise. -/
axiom UCComposition : Prop

end VoltaZk.Ideal

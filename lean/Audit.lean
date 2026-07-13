import VoltaZk

/-!
Machine-readable named-assumption audit for the frozen M1–M9 boundary.

Run with `lake env lean Audit.lean`. None of the four declarations in
`VoltaZk.Ideal` should appear below; M9 carries `BindsIntoMac` as an explicit
theorem hypothesis rather than importing the global PCS placeholder.

The first block is the generic M1--M9 boundary. The second block audits the
scalar-power soundness theorems that match Rust's concrete
`chi^(j+1)` batching format; keeping both blocks prevents the stronger generic
vector-RLC bounds from being mistaken for implementation bounds.
-/

#print axioms VoltaZk.bsc_zeroBatch_perfect_zk
#print axioms VoltaZk.blind_sumcheck_sound
#print axioms VoltaZk.authenticated_cache_sound
#print axioms VoltaZk.sub_zeroOpen_sound
#print axioms VoltaZk.sequential_composition_perfect_zk
#print axioms VoltaZk.prod_perfect_sim
#print axioms VoltaZk.prodBatch_sound
#print axioms VoltaZk.PCSOpening.opening_mac_sound

-- Concrete Rust scalar-power batching map.
#print axioms VoltaZk.card_scalarRlc_zero_le
#print axioms VoltaZk.zeroBatch_sound_scalar
#print axioms VoltaZk.prodBatch_sound_scalar
#print axioms VoltaZk.blind_sumcheck_sound_scalar
#print axioms VoltaZk.kv_cache_sound_scalar
#print axioms VoltaZk.authenticated_cache_sound_scalar

-- P7 shared-round outer scalar batch: K fixed claims, one common r.
#print axioms VoltaZk.outer_scalar_batch_blind_sumcheck_sound
#print axioms VoltaZk.scalar_batch_blind_sumcheck_sound

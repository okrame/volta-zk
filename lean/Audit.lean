import VoltaZk

/-!
Machine-readable named-assumption audit for the frozen M1–M9 boundary.

Run with `lake env lean Audit.lean`. None of the four declarations in
`VoltaZk.Ideal` should appear below; M9 carries `BindsIntoMac` as an explicit
theorem hypothesis rather than importing the global PCS placeholder.
-/

#print axioms VoltaZk.bsc_zeroBatch_perfect_zk
#print axioms VoltaZk.blind_sumcheck_sound
#print axioms VoltaZk.authenticated_cache_sound
#print axioms VoltaZk.sub_zeroOpen_sound
#print axioms VoltaZk.sequential_composition_perfect_zk
#print axioms VoltaZk.prod_perfect_sim
#print axioms VoltaZk.prodBatch_sound
#print axioms VoltaZk.PCSOpening.opening_mac_sound

import Mathlib.FieldTheory.Finite.GaloisField
import Mathlib.GroupTheory.SpecificGroups.Cyclic
import Mathlib.NumberTheory.LucasPrimality

/-! # X4 concrete Goldilocks quadratic field -/

namespace VoltaZk

/-- The Goldilocks prime `2^64 - 2^32 + 1`. -/
def goldilocksP : Nat := 18446744069414584321

private lemma x4_modEq_pow_bit {m a e r r' bit enext : Nat}
    (henext : enext = e * 2 + bit)
    (h : a ^ e ≡ r [MOD m])
    (hstep : r ^ 2 * a ^ bit ≡ r' [MOD m]) :
    a ^ enext ≡ r' [MOD m] := by
  subst enext
  calc
    a ^ (e * 2 + bit) = (a ^ e) ^ 2 * a ^ bit := by rw [pow_add, pow_mul]
    _ ≡ r ^ 2 * a ^ bit [MOD m] := (h.pow 2).mul (Nat.ModEq.refl _)
    _ ≡ r' [MOD m] := hstep

/-- A kernel-checked square-and-multiply certificate for the Proth witness `7`. -/
private theorem goldilocks_proth_certificate :
    (7 : ZMod goldilocksP) ^ ((goldilocksP - 1) / 2) = -1 := by
  have h0 : 7 ^ 1 ≡ 7 [MOD goldilocksP] := Nat.ModEq.refl 7
  have h1 : 7 ^ 3 ≡ 343 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 343) (by norm_num) h0
      (by norm_num [goldilocksP, Nat.ModEq])
  have h2 : 7 ^ 7 ≡ 823543 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 823543) (by norm_num) h1
      (by norm_num [goldilocksP, Nat.ModEq])
  have h3 : 7 ^ 15 ≡ 4747561509943 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 4747561509943) (by norm_num) h2
      (by norm_num [goldilocksP, Nat.ModEq])
  have h4 : 7 ^ 31 ≡ 11074261478625843323 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 11074261478625843323) (by norm_num) h3
      (by norm_num [goldilocksP, Nat.ModEq])
  have h5 : 7 ^ 63 ≡ 12148266161370408270 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 12148266161370408270) (by norm_num) h4
      (by norm_num [goldilocksP, Nat.ModEq])
  have h6 : 7 ^ 127 ≡ 7007601668316978083 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 7007601668316978083) (by norm_num) h5
      (by norm_num [goldilocksP, Nat.ModEq])
  have h7 : 7 ^ 255 ≡ 8125271997680889877 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 8125271997680889877) (by norm_num) h6
      (by norm_num [goldilocksP, Nat.ModEq])
  have h8 : 7 ^ 511 ≡ 2624486902016877951 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 2624486902016877951) (by norm_num) h7
      (by norm_num [goldilocksP, Nat.ModEq])
  have h9 : 7 ^ 1023 ≡ 8253119735826302939 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 8253119735826302939) (by norm_num) h8
      (by norm_num [goldilocksP, Nat.ModEq])
  have h10 : 7 ^ 2047 ≡ 3543566522599720475 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 3543566522599720475) (by norm_num) h9
      (by norm_num [goldilocksP, Nat.ModEq])
  have h11 : 7 ^ 4095 ≡ 11981551684735969599 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 11981551684735969599) (by norm_num) h10
      (by norm_num [goldilocksP, Nat.ModEq])
  have h12 : 7 ^ 8191 ≡ 10062120588441922115 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 10062120588441922115) (by norm_num) h11
      (by norm_num [goldilocksP, Nat.ModEq])
  have h13 : 7 ^ 16383 ≡ 10485806445487905393 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 10485806445487905393) (by norm_num) h12
      (by norm_num [goldilocksP, Nat.ModEq])
  have h14 : 7 ^ 32767 ≡ 4139485063330164956 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 4139485063330164956) (by norm_num) h13
      (by norm_num [goldilocksP, Nat.ModEq])
  have h15 : 7 ^ 65535 ≡ 12134830135347446949 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 12134830135347446949) (by norm_num) h14
      (by norm_num [goldilocksP, Nat.ModEq])
  have h16 : 7 ^ 131071 ≡ 4326791766630348883 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 4326791766630348883) (by norm_num) h15
      (by norm_num [goldilocksP, Nat.ModEq])
  have h17 : 7 ^ 262143 ≡ 206761543466863628 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 206761543466863628) (by norm_num) h16
      (by norm_num [goldilocksP, Nat.ModEq])
  have h18 : 7 ^ 524287 ≡ 10086585273483141421 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 10086585273483141421) (by norm_num) h17
      (by norm_num [goldilocksP, Nat.ModEq])
  have h19 : 7 ^ 1048575 ≡ 1855730417186139594 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 1855730417186139594) (by norm_num) h18
      (by norm_num [goldilocksP, Nat.ModEq])
  have h20 : 7 ^ 2097151 ≡ 7626447102712710903 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 7626447102712710903) (by norm_num) h19
      (by norm_num [goldilocksP, Nat.ModEq])
  have h21 : 7 ^ 4194303 ≡ 7790920094560990216 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 7790920094560990216) (by norm_num) h20
      (by norm_num [goldilocksP, Nat.ModEq])
  have h22 : 7 ^ 8388607 ≡ 5901922255895126089 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 5901922255895126089) (by norm_num) h21
      (by norm_num [goldilocksP, Nat.ModEq])
  have h23 : 7 ^ 16777215 ≡ 8935258787870022506 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 8935258787870022506) (by norm_num) h22
      (by norm_num [goldilocksP, Nat.ModEq])
  have h24 : 7 ^ 33554431 ≡ 13093775858033092690 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 13093775858033092690) (by norm_num) h23
      (by norm_num [goldilocksP, Nat.ModEq])
  have h25 : 7 ^ 67108863 ≡ 11243737384857129666 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 11243737384857129666) (by norm_num) h24
      (by norm_num [goldilocksP, Nat.ModEq])
  have h26 : 7 ^ 134217727 ≡ 2063617152444052883 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 2063617152444052883) (by norm_num) h25
      (by norm_num [goldilocksP, Nat.ModEq])
  have h27 : 7 ^ 268435455 ≡ 13064848991504552222 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 13064848991504552222) (by norm_num) h26
      (by norm_num [goldilocksP, Nat.ModEq])
  have h28 : 7 ^ 536870911 ≡ 16593403251012455084 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 16593403251012455084) (by norm_num) h27
      (by norm_num [goldilocksP, Nat.ModEq])
  have h29 : 7 ^ 1073741823 ≡ 5859133952941131217 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 5859133952941131217) (by norm_num) h28
      (by norm_num [goldilocksP, Nat.ModEq])
  have h30 : 7 ^ 2147483647 ≡ 15659105665374529263 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 15659105665374529263) (by norm_num) h29
      (by norm_num [goldilocksP, Nat.ModEq])
  have h31 : 7 ^ 4294967295 ≡ 1753635133440165772 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 1) (r' := 1753635133440165772) (by norm_num) h30
      (by norm_num [goldilocksP, Nat.ModEq])
  have h32 : 7 ^ 8589934590 ≡ 4614640910117430873 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 4614640910117430873) (by norm_num) h31
      (by norm_num [goldilocksP, Nat.ModEq])
  have h33 : 7 ^ 17179869180 ≡ 9123114210336311365 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 9123114210336311365) (by norm_num) h32
      (by norm_num [goldilocksP, Nat.ModEq])
  have h34 : 7 ^ 34359738360 ≡ 16116352524544190054 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 16116352524544190054) (by norm_num) h33
      (by norm_num [goldilocksP, Nat.ModEq])
  have h35 : 7 ^ 68719476720 ≡ 6414415596519834757 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 6414415596519834757) (by norm_num) h34
      (by norm_num [goldilocksP, Nat.ModEq])
  have h36 : 7 ^ 137438953440 ≡ 1213594585890690845 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 1213594585890690845) (by norm_num) h35
      (by norm_num [goldilocksP, Nat.ModEq])
  have h37 : 7 ^ 274877906880 ≡ 17096174751763063430 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17096174751763063430) (by norm_num) h36
      (by norm_num [goldilocksP, Nat.ModEq])
  have h38 : 7 ^ 549755813760 ≡ 5456943929260765144 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 5456943929260765144) (by norm_num) h37
      (by norm_num [goldilocksP, Nat.ModEq])
  have h39 : 7 ^ 1099511627520 ≡ 9713644485405565297 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 9713644485405565297) (by norm_num) h38
      (by norm_num [goldilocksP, Nat.ModEq])
  have h40 : 7 ^ 2199023255040 ≡ 16905767614792059275 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 16905767614792059275) (by norm_num) h39
      (by norm_num [goldilocksP, Nat.ModEq])
  have h41 : 7 ^ 4398046510080 ≡ 5416168637041100469 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 5416168637041100469) (by norm_num) h40
      (by norm_num [goldilocksP, Nat.ModEq])
  have h42 : 7 ^ 8796093020160 ≡ 17654865857378133588 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17654865857378133588) (by norm_num) h41
      (by norm_num [goldilocksP, Nat.ModEq])
  have h43 : 7 ^ 17592186040320 ≡ 3511170319078647661 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 3511170319078647661) (by norm_num) h42
      (by norm_num [goldilocksP, Nat.ModEq])
  have h44 : 7 ^ 35184372080640 ≡ 18146160046829613826 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 18146160046829613826) (by norm_num) h43
      (by norm_num [goldilocksP, Nat.ModEq])
  have h45 : 7 ^ 70368744161280 ≡ 9306717745644682924 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 9306717745644682924) (by norm_num) h44
      (by norm_num [goldilocksP, Nat.ModEq])
  have h46 : 7 ^ 140737488322560 ≡ 12380578893860276750 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 12380578893860276750) (by norm_num) h45
      (by norm_num [goldilocksP, Nat.ModEq])
  have h47 : 7 ^ 281474976645120 ≡ 6115771955107415310 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 6115771955107415310) (by norm_num) h46
      (by norm_num [goldilocksP, Nat.ModEq])
  have h48 : 7 ^ 562949953290240 ≡ 17776499369601055404 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17776499369601055404) (by norm_num) h47
      (by norm_num [goldilocksP, Nat.ModEq])
  have h49 : 7 ^ 1125899906580480 ≡ 16207902636198568418 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 16207902636198568418) (by norm_num) h48
      (by norm_num [goldilocksP, Nat.ModEq])
  have h50 : 7 ^ 2251799813160960 ≡ 1532612707718625687 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 1532612707718625687) (by norm_num) h49
      (by norm_num [goldilocksP, Nat.ModEq])
  have h51 : 7 ^ 4503599626321920 ≡ 17492915097719143606 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17492915097719143606) (by norm_num) h50
      (by norm_num [goldilocksP, Nat.ModEq])
  have h52 : 7 ^ 9007199252643840 ≡ 455906449640507599 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 455906449640507599) (by norm_num) h51
      (by norm_num [goldilocksP, Nat.ModEq])
  have h53 : 7 ^ 18014398505287680 ≡ 11353340290879379826 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 11353340290879379826) (by norm_num) h52
      (by norm_num [goldilocksP, Nat.ModEq])
  have h54 : 7 ^ 36028797010575360 ≡ 1803076106186727246 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 1803076106186727246) (by norm_num) h53
      (by norm_num [goldilocksP, Nat.ModEq])
  have h55 : 7 ^ 72057594021150720 ≡ 13797081185216407910 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 13797081185216407910) (by norm_num) h54
      (by norm_num [goldilocksP, Nat.ModEq])
  have h56 : 7 ^ 144115188042301440 ≡ 17870292113338400769 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17870292113338400769) (by norm_num) h55
      (by norm_num [goldilocksP, Nat.ModEq])
  have h57 : 7 ^ 288230376084602880 ≡ 549755813888 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 549755813888) (by norm_num) h56
      (by norm_num [goldilocksP, Nat.ModEq])
  have h58 : 7 ^ 576460752169205760 ≡ 70368744161280 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 70368744161280) (by norm_num) h57
      (by norm_num [goldilocksP, Nat.ModEq])
  have h59 : 7 ^ 1152921504338411520 ≡ 17293822564807737345 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 17293822564807737345) (by norm_num) h58
      (by norm_num [goldilocksP, Nat.ModEq])
  have h60 : 7 ^ 2305843008676823040 ≡ 18446744069397807105 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 18446744069397807105) (by norm_num) h59
      (by norm_num [goldilocksP, Nat.ModEq])
  have h61 : 7 ^ 4611686017353646080 ≡ 281474976710656 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 281474976710656) (by norm_num) h60
      (by norm_num [goldilocksP, Nat.ModEq])
  have h62 : 7 ^ 9223372034707292160 ≡ 18446744069414584320 [MOD goldilocksP] :=
    x4_modEq_pow_bit (bit := 0) (r' := 18446744069414584320) (by norm_num) h61
      (by norm_num [goldilocksP, Nat.ModEq])
  have hneg : (((goldilocksP - 1 : Nat) : ZMod goldilocksP)) = -1 := by
    rw [Nat.cast_sub (by norm_num [goldilocksP])]
    rw [ZMod.natCast_self]
    simp
  calc
    (7 : ZMod goldilocksP) ^ ((goldilocksP - 1) / 2) =
        ((7 ^ ((goldilocksP - 1) / 2) : Nat) : ZMod goldilocksP) :=
      (Nat.cast_pow 7 _).symm
    _ = (((goldilocksP - 1 : Nat) : ZMod goldilocksP)) := by
      apply (ZMod.natCast_eq_natCast_iff _ _ _).2
      convert h62 using 1 <;> norm_num [goldilocksP]
    _ = -1 := hneg

/-- Primality of the Goldilocks modulus, via the explicit Proth certificate above. -/
theorem goldilocksP_prime : Nat.Prime goldilocksP := by
  rw [Nat.prime_def_le_sqrt]
  constructor
  · norm_num [goldilocksP]
  intro m hm2 hmsqrt hmp
  have hm0 : m ≠ 0 := by omega
  letI : NeZero m := ⟨hm0⟩
  have hm_ne_two : m ≠ 2 := by
    rintro rfl
    norm_num [goldilocksP] at hmp
  have hmgt2 : 2 < m := by omega
  letI : Fact (2 < m) := ⟨hmgt2⟩
  have hmap := congrArg (ZMod.castHom hmp (ZMod m)) goldilocks_proth_certificate
  have hmap' : (7 : ZMod m) ^ ((goldilocksP - 1) / 2) = -1 := by
    simpa only [map_pow, map_neg, map_one, map_ofNat] using hmap
  let y : ZMod m := (7 : ZMod m) ^ (2 ^ 32 - 1)
  have hyhalf : y ^ (2 ^ 31) = -1 := by
    change ((7 : ZMod m) ^ (2 ^ 32 - 1)) ^ (2 ^ 31) = -1
    rw [← pow_mul]
    convert hmap' using 1 <;> norm_num [goldilocksP]
  have hyfull : y ^ (2 ^ 32) = 1 := by
    rw [show 2 ^ 32 = 2 ^ 31 * 2 by norm_num, pow_mul, hyhalf]
    norm_num
  have hyunit : IsUnit y := IsUnit.of_pow_eq_one hyfull (by norm_num)
  let u : (ZMod m)ˣ := hyunit.unit
  have hupow : u ^ (2 ^ 32) = 1 := by
    apply Units.ext
    simpa [u, Units.val_pow_eq_pow_val, hyunit.unit_spec] using hyfull
  have huhalf : u ^ (2 ^ 31) ≠ 1 := by
    intro hu
    have hval := congrArg (fun v : (ZMod m)ˣ => (v : ZMod m)) hu
    simp only [Units.val_pow_eq_pow_val, Units.val_one] at hval
    have hval' : y ^ (2 ^ 31) = (1 : ZMod m) := by
      simpa [u, hyunit.unit_spec] using hval
    exact ZMod.neg_one_ne_one (hyhalf.symm.trans hval')
  have hord_dvd : orderOf u ∣ 2 ^ 32 := orderOf_dvd_of_pow_eq_one hupow
  obtain ⟨j, hjle, hord⟩ := (Nat.dvd_prime_pow Nat.prime_two).1 hord_dvd
  have hj : j = 32 := by
    by_contra hjne
    have hj31 : j ≤ 31 := by omega
    have hsmall : orderOf u ∣ 2 ^ 31 := by
      rw [hord]
      exact pow_dvd_pow 2 hj31
    exact huhalf ((orderOf_dvd_iff_pow_eq_one).1 hsmall)
  have hord_eq : orderOf u = 2 ^ 32 := by simpa [hj] using hord
  have hcard : Fintype.card (ZMod m)ˣ ≤ m - 1 :=
    Nat.card_units_zmod_lt_sub_one (by omega)
  have hlower : 2 ^ 32 ≤ m - 1 := by
    rw [← hord_eq]
    exact orderOf_le_card_univ.trans hcard
  have hsqrt : Nat.sqrt goldilocksP < 2 ^ 32 := by
    rw [Nat.sqrt_lt']
    norm_num [goldilocksP]
  omega

instance goldilocksP.factPrime : Fact (Nat.Prime goldilocksP) :=
  ⟨goldilocksP_prime⟩

/-- An abstract presentation of the unique finite field with `p^2` elements.
It is isomorphic to the concrete `F_p[phi]/(phi^2-7)` wire representation. -/
abbrev X4E := GaloisField goldilocksP 2

noncomputable instance : Fintype X4E := Fintype.ofFinite X4E

theorem goldilocks_fp2_card :
    Fintype.card X4E =
      340282366762482138490186164457219031041 := by
  rw [Fintype.card_eq_nat_card,
    GaloisField.card goldilocksP 2 (by norm_num)]
  norm_num [goldilocksP]

theorem goldilocks_fp2_two_adicity :
    2^33 ∣ (Fintype.card X4E - 1) ∧
      ¬ 2^34 ∣ (Fintype.card X4E - 1) := by
  rw [goldilocks_fp2_card]
  norm_num

private theorem x4_pow_two_dvd_card_sub_one {logN : Nat}
    (hlog : logN ≤ 33) :
    2 ^ logN ∣ Fintype.card X4E - 1 := by
  have hpow : 2 ^ logN ∣ 2 ^ 33 := pow_dvd_pow 2 hlog
  exact hpow.trans goldilocks_fp2_two_adicity.1

private theorem x4_domain_root_unit {logN : Nat} (hlog : logN ≤ 33) :
    ∃ omega : X4Eˣ, orderOf omega = 2 ^ logN := by
  classical
  obtain ⟨g, hg⟩ := IsCyclic.exists_generator (α := X4Eˣ)
  have hgord : orderOf g = Fintype.card X4E - 1 := by
    rw [orderOf_eq_card_of_forall_mem_zpowers hg,
      Nat.card_eq_fintype_card, Fintype.card_units]
  let n := 2 ^ logN
  have hn : n ∣ orderOf g := by
    rw [hgord]
    exact x4_pow_two_dvd_card_sub_one hlog
  refine ⟨g ^ (orderOf g / n), ?_⟩
  rw [orderOf_pow,
    Nat.gcd_eq_right_iff_dvd.mpr (Nat.div_dvd_of_dvd hn)]
  exact Nat.div_div_self hn (orderOf_pos g).ne'

theorem goldilocks_fp2_domain_root {logN : Nat}
    (hlog : logN ≤ 33) :
    ∃ omega : X4E, orderOf omega = 2^logN := by
  obtain ⟨u, hu⟩ := x4_domain_root_unit hlog
  exact ⟨(u : X4E), (orderOf_units (y := u)).trans hu⟩

end VoltaZk

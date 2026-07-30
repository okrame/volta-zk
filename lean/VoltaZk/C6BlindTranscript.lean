import VoltaZk.BoundaryThinningSound
import VoltaZk.C6Amplification
import Mathlib.Tactic

/-!
# C6 dual-tape blind residual transcript

This additive module closes the algebraic seams introduced by the C6RSC3
blind-transcript amendment.  It does not alter the frozen M1--M11 results.

* The uncompressed first message authenticates values at both Boolean
  endpoints.  Their sum is the live family claim used by the existing
  compressed M3/M11 recursion.
* The activation ZeroOpen binds the independently sealed leaf and auxiliary
  first messages to the public complete-relation target before the shared
  challenge is released.
* Exactly eight auxiliary products and two terminal zero rows specialize the
  existing scalar-power ProductClosure and ZeroBatch theorems.
* The exact scalar-power root census is `91 + 1 + 10 + 3 = 105`, below the
  conservative per-complete-repetition allocation of 256.
* Two independently domain-separated complete proof repetitions square that
  allocation.  Unioning the fixed-relation and blind-transcript branches
  contributes the preregistered numerator `2^17`.

Every complete proof repetition checks both MAC coordinates.  Authenticating
the same hidden scalar on both coordinates can only strengthen the
single-coordinate bounds used below; it is not confused with the two
independent proof repetitions that provide the square.
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F]

/-! ## Full first-round message and activation -/

/-- C6RSC3's uncompressed first message.  Components are adversarial
plaintext/tag pairs fixed before the corresponding verifier challenge. -/
inductive C6FullFirstRoundWire (F : Type*) where
  | quadratic (g0 g1 g2 : F × F)
  | cubic (g0 g1 g2 g3 : F × F)

namespace C6FullFirstRoundWire

/-- The live family claim is derived from the two sent Boolean endpoints. -/
def initialClaimX : C6FullFirstRoundWire F → F
  | .quadratic g0 g1 _ => g0.1 + g1.1
  | .cubic g0 g1 _ _ => g0.1 + g1.1

/-- Drop the now-derived node-one value and enter the frozen compressed
M3/M11 grammar. -/
def toCompressed : C6FullFirstRoundWire F → LateRoundWire F
  | .quadratic g0 _ g2 => .quadratic g0 g2
  | .cubic g0 _ g2 g3 => .cubic g0 g2 g3

/-- Polynomial interpolated from every explicitly sent first-round node. -/
noncomputable def polynomial : C6FullFirstRoundWire F → Polynomial F
  | .quadratic g0 g1 g2 =>
      polyOfCoeffs (quadraticCoeffs g0.1 g1.1 g2.1)
  | .cubic g0 g1 g2 g3 =>
      polyOfCoeffs (cubicCoeffs g0.1 g1.1 g2.1 g3.1)

/-- Authenticated live claim obtained by locally adding the two endpoint
claims. -/
def initialAuthed (Delta : F) : C6FullFirstRoundWire F → Authed F
  | .quadratic g0 g1 _ => authedOfPair Delta g0 + authedOfPair Delta g1
  | .cubic g0 g1 _ _ => authedOfPair Delta g0 + authedOfPair Delta g1

theorem initialAuthed_valid (wire : C6FullFirstRoundWire F) (Delta : F) :
    (wire.initialAuthed Delta).Valid Delta := by
  cases wire <;>
    exact (authedOfPair_valid Delta _).add (authedOfPair_valid Delta _)

@[simp] theorem initialAuthed_x (wire : C6FullFirstRoundWire F) (Delta : F) :
    (wire.initialAuthed Delta).x = wire.initialClaimX := by
  cases wire <;> rfl

/-- Reconstructing node one from the derived initial claim gives exactly the
polynomial interpolated from the full first message. -/
theorem compressedRoundPoly_initialClaim
    (wire : C6FullFirstRoundWire F) :
    compressedRoundPoly wire.initialClaimX wire.toCompressed
      = wire.polynomial := by
  cases wire with
  | quadratic g0 g1 g2 =>
      simp only [initialClaimX, toCompressed, polynomial, compressedRoundPoly]
      rw [show g0.1 + g1.1 - g0.1 = g1.1 by ring]
  | cubic g0 g1 g2 g3 =>
      simp only [initialClaimX, toCompressed, polynomial, compressedRoundPoly]
      rw [show g0.1 + g1.1 - g0.1 = g1.1 by ring]

/-- The full first message closes the same Boolean-sum relation consumed by
the later compressed recursion. -/
theorem polynomial_sum01 (wire : C6FullFirstRoundWire F) :
    wire.polynomial.eval 0 + wire.polynomial.eval 1
      = wire.initialClaimX := by
  rw [← compressedRoundPoly_initialClaim]
  exact compressedRoundPoly_sum01 wire.initialClaimX wire.toCompressed

end C6FullFirstRoundWire

/-- Authenticated activation residual checked before the shared challenge. -/
def c6ActivationResidual (Delta : F)
    (leaf auxiliary : C6FullFirstRoundWire F) (target : F) : Authed F :=
  leaf.initialAuthed Delta + auxiliary.initialAuthed Delta
    - Authed.ofPublic Delta target

theorem c6_activation_residual_valid (Delta : F)
    (leaf auxiliary : C6FullFirstRoundWire F) (target : F) :
    (c6ActivationResidual Delta leaf auxiliary target).Valid Delta :=
  ((leaf.initialAuthed_valid Delta).add
    (auxiliary.initialAuthed_valid Delta)).sub
      (Authed.ofPublic_valid Delta target)

/-- A successful activation ZeroOpen binds both sealed first messages to the
public target and therefore starts the same two-family relation as the clear
reference sumcheck. -/
theorem c6_full_first_round_activation_closes (Delta : F)
    (leaf auxiliary : C6FullFirstRoundWire F) (target : F)
    (hzero : (c6ActivationResidual Delta leaf auxiliary target).x = 0) :
    leaf.polynomial.eval 0 + leaf.polynomial.eval 1
      + (auxiliary.polynomial.eval 0 + auxiliary.polynomial.eval 1)
        = target := by
  rw [leaf.polynomial_sum01, auxiliary.polynomial_sum01]
  simpa [c6ActivationResidual] using (sub_eq_zero.mp hzero)

/-! ## Exact eight-product/two-row terminal closure -/

/-- One terminal linear expression with the exact C6 leaf-table census. -/
def c6LeafTerminalExpression
    (coeff value : Fin 8 → F) : F :=
  ∑ i, coeff i * value i

/-- One terminal auxiliary expression with sixteen linear table values and
the eight separately authenticated quadratic values. -/
def c6AuxiliaryTerminalExpression
    (linearCoeff linearValue : Fin 16 → F)
    (productCoeff productValue : Fin 8 → F) : F :=
  (∑ i, linearCoeff i * linearValue i)
    + ∑ i, productCoeff i * productValue i

/-- If the eight ProductClosure outputs are the intended products and both
terminal residual rows are zero, the two family claims equal the exact
terminal expressions. -/
theorem c6_terminal_eight_products_two_zero_rows_close
    (leafCoeff leafValue : Fin 8 → F)
    (auxiliaryCoeff auxiliaryValue : Fin 16 → F)
    (productCoeff productValue lhs rhs : Fin 8 → F)
    (leafClaim auxiliaryClaim : F)
    (hproduct : ∀ i, productValue i = lhs i * rhs i)
    (hleaf : c6LeafTerminalExpression leafCoeff leafValue - leafClaim = 0)
    (hauxiliary :
      c6AuxiliaryTerminalExpression auxiliaryCoeff auxiliaryValue
        productCoeff productValue - auxiliaryClaim = 0) :
    leafClaim = c6LeafTerminalExpression leafCoeff leafValue ∧
      auxiliaryClaim =
        c6AuxiliaryTerminalExpression auxiliaryCoeff auxiliaryValue
          productCoeff (fun i => lhs i * rhs i) := by
  constructor
  · exact (sub_eq_zero.mp hleaf).symm
  · have hvalues : productValue = fun i => lhs i * rhs i := funext hproduct
    rw [hvalues] at hauxiliary
    exact (sub_eq_zero.mp hauxiliary).symm

/-- Exact eight-triple specialization of the existing algebraic
ProductClosure theorem. -/
theorem c6_eight_product_closure (Delta : F)
    (a b c : Fin 8 → Authed F) (mask : Authed F) (chi : F)
    (ha : ∀ j, (a j).Valid Delta) (hb : ∀ j, (b j).Valid Delta)
    (hc : ∀ j, (c j).Valid Delta) (hmask : mask.Valid Delta)
    (hq : c6ProductQ a b c chi = 0) :
    c6ProductKeySide Delta a b c mask chi
      = c6ProductM0 a b c mask chi
        + c6ProductM1 a b c mask chi * Delta :=
  c6_product_closure Delta a b c mask chi ha hb hc hmask hq

variable [Fintype F] [DecidableEq F]

/-- Rust uses `chi^(j+1)`: eight terminal products therefore instantiate the
M8 scalar-power numerator as `8+2 = 10`, not the sharper vector-RLC value
three. -/
theorem c6_eight_product_closure_sound_scalar
    (z : Fin 8 → ProdClaim F) {j0 : Fin 8}
    (hz : (z j0).c.1 ≠ (z j0).a.1 * (z j0).b.1) (mask : F × F)
    (msg : F → F × F) :
    (univ.filter fun DeltaChi : F × F =>
        (msg DeltaChi.2).1 + (msg DeltaChi.2).2 * DeltaChi.1
          = ∑ j, DeltaChi.2 ^ (j.val + 1) * prodKey DeltaChi.1 (z j)
              + keyOf DeltaChi.1 mask).card
      ≤ 10 * Fintype.card F := by
  simpa using prodBatch_sound_scalar z hz mask msg

/-- Two scalar-power terminal zero rows instantiate M3a with numerator
`2+1 = 3`. -/
theorem c6_two_terminal_rows_zeroBatch_sound_scalar
    (z : Fin 2 → F × F) {j0 : Fin 2} (hz : (z j0).1 ≠ 0)
    (msg : F → F) :
    (univ.filter fun DeltaChi : F × F =>
      msg DeltaChi.2 =
        ∑ j, DeltaChi.2 ^ (j.val + 1) * keyOf DeltaChi.1 (z j)).card
      ≤ 3 * Fintype.card F := by
  simpa using zeroBatch_sound_scalar z hz msg

/-! ## Root census and amplified event union -/

def c6BlindSumcheckDegreeRoots : Nat := 2 * 23 + 3 * 15
def c6BlindActivationRoots : Nat := 1
def c6BlindTerminalProductRoots : Nat := 8 + 2
def c6BlindTerminalZeroBatchRoots : Nat := 2 + 1

def c6BlindTranscriptRoots : Nat :=
  c6BlindSumcheckDegreeRoots
    + c6BlindActivationRoots
    + c6BlindTerminalProductRoots
    + c6BlindTerminalZeroBatchRoots

theorem c6_blind_transcript_root_census :
    c6BlindTranscriptRoots = 105 := by
  norm_num [c6BlindTranscriptRoots, c6BlindSumcheckDegreeRoots,
    c6BlindActivationRoots, c6BlindTerminalProductRoots,
    c6BlindTerminalZeroBatchRoots]

theorem c6_blind_transcript_root_census_le_256 :
    c6BlindTranscriptRoots ≤ 256 := by
  rw [c6_blind_transcript_root_census]
  norm_num

/-- Two independent complete proof repetitions square the conservative
256-root bound.  Each repetition is a complete relation over both MAC
coordinates. -/
theorem c6_blind_two_repetition_card_le_256
    {Omega0 Omega1 : Type*}
    [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1)
    (h0 : bad0.card ≤ 256) (h1 : bad1.card ≤ 256) :
    (c6IndependentPairAccepting bad0 bad1).card ≤ 256 ^ 2 :=
  c6_independent_pair_accepting_card_le bad0 bad1 h0 h1

/-- Union of the fixed-relation and blind-transcript amplified branches.
Both branch sets already live in the product space of the two independent
complete proof repetitions. -/
theorem c6_clear_blind_union_card_le
    {Omega : Type*} [DecidableEq Omega]
    (clearRelation blindTranscript : Finset Omega) {B : Nat}
    (hclear : clearRelation.card ≤ B ^ 2)
    (hblind : blindTranscript.card ≤ B ^ 2) :
    (clearRelation ∪ blindTranscript).card ≤ 2 * B ^ 2 := by
  calc
    (clearRelation ∪ blindTranscript).card
        ≤ clearRelation.card + blindTranscript.card :=
      Finset.card_union_le clearRelation blindTranscript
    _ ≤ B ^ 2 + B ^ 2 := Nat.add_le_add hclear hblind
    _ = 2 * B ^ 2 := by ring

theorem c6_clear_blind_union_card_le_2_pow_17
    {Omega : Type*} [DecidableEq Omega]
    (clearRelation blindTranscript : Finset Omega)
    (hclear : clearRelation.card ≤ 256 ^ 2)
    (hblind : blindTranscript.card ≤ 256 ^ 2) :
    (clearRelation ∪ blindTranscript).card ≤ 2 ^ 17 := by
  simpa using
    (c6_clear_blind_union_card_le clearRelation blindTranscript hclear hblind)

/-- Exact Goldilocks-`Fp2` certificate for the amended residual event:
`2^17/|Fp2|^2 < 2^-238`. -/
theorem c6_delta_blind_wrapper_event_better_than_238 :
    (2 ^ 17) * 2 ^ 238 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

/-- Exact certificate for the separately named hidden-u plus
authenticated-output-link event allocation. -/
theorem c6_linear_link_event_better_than_239 :
    (2 ^ 16) * 2 ^ 239 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

end VoltaZk

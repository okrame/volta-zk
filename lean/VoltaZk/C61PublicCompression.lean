import VoltaZk.C6PersistentCache
import VoltaZk.C6Amplification
import VoltaZk.Counting
import Mathlib.Algebra.MvPolynomial.SchwartzZippel
import Mathlib.Data.Matrix.Mul
import Mathlib.Tactic

/-!
# C6.1 response-local public compression

This additive module records the algebraic boundary selected by C6.1 Gate 2.
It does not alter the frozen M1--M11 statements or claim security of a
concrete WHIR implementation.  The load-bearing facts here are:

* challenge-bearing discrepancy polynomials are fixed before their MLE
  points and pay their total degree over the field;
* the 64 public terminal claims are fixed before their scalar-power RLC;
* one reverse adjoint transfers the batched terminal claim to the source
  boundary of the fixed public linear DAG;
* public acceptance composes with, but never learns or replaces, the
  designated-verifier closure;
* durable state advances only from the exact accepted predecessor; and
* the exact registered rational error sum clears both the per-certificate
  and 17-certificate targets.

PCS binding and HVZK privacy remain explicit backend premises.  The
authenticated-target amendment below proves its linear MAC seam and the
75-bit-plus-MAC two-chain bound, but not claim privacy for a concrete modified
WHIR implementation.  The Rust typestate and codec must instantiate the same
message order and may not turn those premises into unchecked metadata.
-/

namespace VoltaZk

open Finset Matrix

/-! ## Frozen challenge and operation census -/

def c61AlphaStreams : Nat := 2
def c61AlphaPointDimension : Nat := 23
def c61TerminalStreams : Nat := 8
def c61TerminalPointDimension : Nat := 17
def c61AtomicStreams : Nat := 2
def c61AtomicPointDimension : Nat := 26

def c61EqualityChallengeElements : Nat :=
  c61AlphaStreams * c61AlphaPointDimension
    + c61TerminalStreams * c61TerminalPointDimension
    + c61AtomicStreams * c61AtomicPointDimension

theorem c61_equality_challenge_census :
    c61EqualityChallengeElements = 234 := by
  norm_num [c61EqualityChallengeElements, c61AlphaStreams,
    c61AlphaPointDimension, c61TerminalStreams,
    c61TerminalPointDimension, c61AtomicStreams,
    c61AtomicPointDimension]

def c61CanonicalNodes : Nat := 28_845_631
def c61SourceNodes : Nat := 4_970_850
def c61PublicNodes : Nat := 1_436
def c61StructuralZeroNodes : Nat := 1
def c61AddNodes : Nat := 12_961_295
def c61SubNodes : Nat := 83_197
def c61ScaleNodes : Nat := 10_828_852
def c61SparseOperandEdges : Nat := 36_917_836
def c61RuntimeValues : Nat := 10_830_342

theorem c61_node_partition_census :
    c61SourceNodes + c61PublicNodes + c61StructuralZeroNodes
      + c61AddNodes + c61SubNodes + c61ScaleNodes
      = c61CanonicalNodes := by
  norm_num [c61SourceNodes, c61PublicNodes, c61StructuralZeroNodes,
    c61AddNodes, c61SubNodes, c61ScaleNodes, c61CanonicalNodes]

/-! ## Message order: no challenge before its binding message -/

/-- The response statement and all arrays used by the equality schedules are
bound before the schedule points can be drawn. -/
structure C61RootsFixed (Digest : Type*) where
  statementDigest : Digest
  modelRoot : Digest
  embeddingRoot : Digest
  runtimeRoot : Digest

/-- The 64 terminal claims are a post-schedule, pre-output-challenge message. -/
structure C61TerminalClaimsFixed (Digest F : Type*) extends C61RootsFixed Digest where
  terminalClaims : Fin 64 → F

/-- The aggregate adjoint is committed only after the output challenge. -/
structure C61AdjointFixed (Digest F : Type*) extends C61TerminalClaimsFixed Digest F where
  outputChallenge : F
  adjointRoot : Digest

/-- Deliberately empty: an unbound statement has no schedule-draw transition. -/
structure C61UnboundStatement (Digest : Type*) where
  proposedDigest : Digest

inductive C61CanDrawSchedule {Digest : Type*} :
    C61UnboundStatement Digest → Prop

theorem c61_no_schedule_before_roots {Digest : Type*}
    (statement : C61UnboundStatement Digest) :
    ¬ C61CanDrawSchedule statement := by
  intro h
  exact nomatch h

/-- Deliberately empty: roots without fixed terminal claims cannot issue the
output-batching challenge. -/
inductive C61CanDrawOutputChallenge {Digest F : Type*} :
    C61RootsFixed Digest → Prop

theorem c61_no_output_challenge_before_terminal_claims {Digest F : Type*}
    (roots : C61RootsFixed Digest) :
    ¬ C61CanDrawOutputChallenge (F := F) roots := by
  intro h
  exact nomatch h

/-- Deliberately empty: the native proof challenges cannot be issued while
the aggregate adjoint root is absent. -/
inductive C61CanDrawNativeProofChallenges {Digest F : Type*} :
    C61TerminalClaimsFixed Digest F → Prop

theorem c61_no_native_challenge_before_adjoint {Digest F : Type*}
    (claims : C61TerminalClaimsFixed Digest F) :
    ¬ C61CanDrawNativeProofChallenges claims := by
  intro h
  exact nomatch h

/-! ## Fixed multiaffine discrepancy and terminal batching -/

/-- A discrepancy polynomial fixed before a uniform MLE point pays at most
its total degree divided by the field cardinality.  C6.1 instantiates
`degree <= n` for equality-weighted dimension-`n` relations.  Keeping `p` as
an ordinary theorem argument is the formal non-adaptivity boundary: it cannot
depend on the sampled point `x`. -/
theorem c61_mle_discrepancy_sound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {n : Nat} (p : MvPolynomial (Fin n) F) (hp : p ≠ 0)
    (hdegree : p.totalDegree ≤ n) :
    (#{x ∈ Fintype.piFinset (fun _ : Fin n => (univ : Finset F)) |
        MvPolynomial.eval x p = 0} : ℚ≥0)
        / (Fintype.card F : ℚ≥0) ^ n
      ≤ (n : ℚ≥0) / Fintype.card F := by
  have hsz := MvPolynomial.schwartz_zippel_totalDegree hp (univ : Finset F)
  calc
    (#{x ∈ Fintype.piFinset (fun _ : Fin n => (univ : Finset F)) |
          MvPolynomial.eval x p = 0} : ℚ≥0)
          / (Fintype.card F : ℚ≥0) ^ n
        ≤ (p.totalDegree : ℚ≥0) / Fintype.card F := by
          simpa using hsz
    _ ≤ (n : ℚ≥0) / Fintype.card F := by
      gcongr

/-- The scalar-power polynomial for the 64 terminal errors.  Unlike older C6
batching maps, claim zero has weight one; the maximum degree is therefore 63,
matching the registered `63/|Fp2|` event. -/
noncomputable def c61TerminalRlcPoly
    {F : Type*} [Field F] (error : Fin 64 → F) : Polynomial F :=
  ∑ j, Polynomial.monomial j.val (error j)

theorem c61_terminal_rlc_poly_eval
    {F : Type*} [Field F] (error : Fin 64 → F) (beta : F) :
    (c61TerminalRlcPoly error).eval beta
      = ∑ j, beta ^ j.val * error j := by
  unfold c61TerminalRlcPoly
  rw [Polynomial.eval_finsetSum]
  apply Finset.sum_congr rfl
  intro j _
  rw [Polynomial.eval_monomial]
  exact mul_comm _ _

theorem c61_terminal_rlc_poly_ne_zero
    {F : Type*} [Field F] (error : Fin 64 → F) {j0 : Fin 64}
    (herror : error j0 ≠ 0) : c61TerminalRlcPoly error ≠ 0 := by
  intro hzero
  have hcoeff := congrArg (fun p : Polynomial F => p.coeff j0.val) hzero
  have hcoeff' :
      (∑ j : Fin 64, Polynomial.monomial j.val (error j)).coeff j0.val = 0 := by
    simpa [c61TerminalRlcPoly] using hcoeff
  rw [Polynomial.finsetSum_coeff] at hcoeff'
  simp only [Polynomial.coeff_monomial] at hcoeff'
  have hsum :
      (∑ j : Fin 64, if j.val = j0.val then error j else 0) = error j0 := by
    classical
    calc
      _ = (if j0.val = j0.val then error j0 else 0) :=
        Finset.sum_eq_single j0 (by
          intro j _ hne
          simp only [ite_eq_right_iff]
          intro heq
          exact (hne (Fin.ext heq)).elim) (by simp)
      _ = error j0 := by simp
  rw [hsum] at hcoeff'
  exact herror hcoeff'

theorem c61_terminal_rlc_poly_degree_le
    {F : Type*} [Field F] (error : Fin 64 → F) :
    (c61TerminalRlcPoly error).natDegree ≤ 63 := by
  unfold c61TerminalRlcPoly
  let f : Fin 64 → Polynomial F := fun j => Polynomial.monomial j.val (error j)
  refine (Polynomial.natDegree_sum_le Finset.univ f).trans ?_
  apply Finset.sup_le
  intro j _
  exact (Polynomial.natDegree_monomial_le (error j)).trans (by omega)

/-- Once all 64 claims are fixed, a false terminal vector survives the fresh
scalar-power output challenge for at most 63 field elements. -/
theorem c61_terminal_output_rlc_sound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    (error : Fin 64 → F) {j0 : Fin 64} (herror : error j0 ≠ 0) :
    (univ.filter fun beta : F =>
      ∑ j, beta ^ j.val * error j = 0).card ≤ 63 := by
  have hne := c61_terminal_rlc_poly_ne_zero error herror
  refine le_trans (Finset.card_le_card ?_)
    ((card_eval_zero_le hne).trans (c61_terminal_rlc_poly_degree_le error))
  intro beta hbeta
  simp only [mem_filter, mem_univ, true_and] at hbeta ⊢
  rw [c61_terminal_rlc_poly_eval]
  exact hbeta

/-- Two independently sampled dimension-24 runtime fingerprints square the
single-fingerprint accepting count.  The per-fingerprint MLE theorem supplies
the two hypotheses in the concrete instantiation. -/
theorem c61_runtime_two_fingerprint_card_le
    {Omega0 Omega1 : Type*} [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1) {fieldCard : Nat}
    (h0 : bad0.card ≤ 24 * fieldCard ^ 23)
    (h1 : bad1.card ≤ 24 * fieldCard ^ 23) :
    (c6IndependentPairAccepting bad0 bad1).card
      ≤ (24 * fieldCard ^ 23) ^ 2 := by
  exact c6_independent_pair_accepting_card_le bad0 bad1 h0 h1

/-! ## Sparse reverse-adjoint terminal link -/

/-- The algebraic core of `C6RSC4-v4`.  `values = source + A*values` is the
fixed public forward DAG and `adjoint = output + A^T*adjoint` is its one
aggregate reverse pass.  If both identities hold, the batched terminal
functional is exactly the source-boundary functional consumed by the
designated closure.  No acyclicity premise is needed for this identity;
acyclicity is needed by the implementation to construct the two witnesses. -/
theorem c61_sparse_adjoint_terminal_link
    {F V : Type*} [CommRing F] [Fintype V]
    (A : Matrix V V F) (source values output adjoint : V → F)
    (hforward : values = source + A *ᵥ values)
    (hadjoint : adjoint = output + Aᵀ *ᵥ adjoint) :
    output ⬝ᵥ values = adjoint ⬝ᵥ source := by
  have houtput : output = adjoint - Aᵀ *ᵥ adjoint := by
    ext i
    have h := congrFun hadjoint i
    dsimp at h ⊢
    linear_combination -h
  have hsource : source = values - A *ᵥ values := by
    ext i
    have h := congrFun hforward i
    dsimp at h ⊢
    linear_combination -h
  calc
    output ⬝ᵥ values
        = (adjoint - Aᵀ *ᵥ adjoint) ⬝ᵥ values := by rw [houtput]
    _ = adjoint ⬝ᵥ values - (Aᵀ *ᵥ adjoint) ⬝ᵥ values := by
      rw [sub_dotProduct]
    _ = adjoint ⬝ᵥ values - adjoint ⬝ᵥ (A *ᵥ values) := by
      rw [dotProduct_comm (Aᵀ *ᵥ adjoint) values,
        Matrix.dotProduct_transpose_mulVec]
    _ = adjoint ⬝ᵥ (values - A *ᵥ values) := by
      rw [dotProduct_sub]
    _ = adjoint ⬝ᵥ source := by rw [hsource]

/-! ## Public-to-designated composition and predecessor state -/

/-- Logical composition boundary.  A public proof may establish the semantic
terminal relation, but a certificate is valid only after the independent
designated closure accepts.  The theorem exposes which side failed; it does
not merge `publicBad` and `designatedBad` into one unnamed event. -/
theorem c61_public_to_designated_composition
    (publicAccept designatedAccept semanticValid certificateValid
      publicBad designatedBad : Prop)
    (hpublic : publicAccept → semanticValid ∨ publicBad)
    (hdesignated : semanticValid → designatedAccept →
      certificateValid ∨ designatedBad)
    (hp : publicAccept) (hd : designatedAccept) :
    certificateValid ∨ publicBad ∨ designatedBad := by
  rcases hpublic hp with hsemantic | hbad
  · rcases hdesignated hsemantic hd with hvalid | hbad
    · exact Or.inl hvalid
    · exact Or.inr (Or.inr hbad)
  · exact Or.inr (Or.inl hbad)

/-! ## Authenticated WHIR target seam -/

/-- The claim-private base closure shifts the public WHIR base claim by one
fresh authenticated mask, then checks only this authenticated residual. -/
def c61AuthenticatedTargetResidual
    {F : Type*} [Field F]
    (Delta gamma combined maskedClaim : F) (target mask : Authed F) :
    Authed F :=
  Authed.ofPublic Delta (combined - (maskedClaim + mask.x))
    - gamma • target + mask

/-- Under the honest unshifted WHIR base identity, the amended residual has
zero plaintext.  In particular, the public equation contains only the
one-time-padded value `gamma * target.x - mask.x`. -/
theorem c61_authenticated_target_residual_x_eq_zero
    {F : Type*} [Field F]
    (Delta gamma combined maskedClaim : F) (target mask : Authed F)
    (hbase : combined = maskedClaim + gamma * target.x) :
    (c61AuthenticatedTargetResidual Delta gamma combined maskedClaim
      target mask).x = 0 := by
  simp [c61AuthenticatedTargetResidual, hbase]

/-- Public embedding and authenticated linearity preserve the MAC invariant;
the verifier needs no target plaintext to derive its residual key. -/
theorem c61_authenticated_target_residual_valid
    {F : Type*} [Field F]
    (Delta gamma combined maskedClaim : F) (target mask : Authed F)
    (htarget : target.Valid Delta) (hmask : mask.Valid Delta) :
    (c61AuthenticatedTargetResidual Delta gamma combined maskedClaim
      target mask).Valid Delta := by
  exact ((Authed.ofPublic_valid Delta
    (combined - (maskedClaim + mask.x))).sub (htarget.smul gamma)).add hmask

/-- Adding a fixed base claim to a field mask is a permutation.  This is the
algebraic equal-fiber fact used by the claim-privacy obligation; the concrete
WHIR simulator remains a backend proof obligation. -/
def c61MaskedClaimShift
    {F : Type*} [AddCommGroup F] (maskedClaim : F) : F ≃ F where
  toFun mask := maskedClaim + mask
  invFun shifted := -maskedClaim + shifted
  left_inv mask := by simp
  right_inv shifted := by simp

theorem c61_masked_claim_shift_bijective
    {F : Type*} [AddCommGroup F] (maskedClaim : F) :
    Function.Bijective (fun mask => maskedClaim + mask) :=
  (c61MaskedClaimShift maskedClaim).bijective

def c61AuthenticatedWhirChains : Nat := 6
def c61AuthenticatedWhirTapes : Nat := 2
def c61AuthenticatedWhirMasksPerTape : Nat := 3

/-- Model, embedding and compiler each contribute one chain to each of the
two independently authenticated tapes. -/
theorem c61_authenticated_whir_mask_census :
    c61AuthenticatedWhirMasksPerTape * c61AuthenticatedWhirTapes
      = c61AuthenticatedWhirChains := by
  norm_num [c61AuthenticatedWhirMasksPerTape, c61AuthenticatedWhirTapes,
    c61AuthenticatedWhirChains]

namespace C6Certificate

/-- C6.1 acceptance keeps the public and designated decisions separate and
requires the exact predecessor-state admissibility predicate. -/
def C61Accepted {Digest Nonce : Type*}
    (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce)
    (publicAccept designatedAccept : Prop) : Prop :=
  publicAccept ∧ designatedAccept ∧ certificate.Admissible state

/-- A C6.1 certificate advances exactly to its claimed new head only after
both layers accept, and the same certificate is then non-replayable. -/
theorem c61_accepted_advances_exact_predecessor
    {Digest Nonce : Type*}
    (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce)
    (publicAccept designatedAccept : Prop)
    (haccept : certificate.C61Accepted state publicAccept designatedAccept) :
    (advance state certificate).head = certificate.newHead
      ∧ (advance state certificate).acceptedCertificate = certificate.digest
      ∧ ¬ certificate.Admissible (advance state certificate) := by
  exact ⟨rfl, rfl, accepted_certificate_not_replayable state certificate haccept.2.2⟩

end C6Certificate

/-! ## Exact rational C6.1 soundness registration -/

def c61GoldilocksP : Nat := goldilocksP

def c61Fp2CardQ : ℚ := (c61GoldilocksP : ℚ) ^ 2

theorem c61_fp2_card_q_eq_x4e :
    c61Fp2CardQ = (Fintype.card X4E : ℚ) := by
  rw [goldilocks_fp2_card]
  norm_num [c61Fp2CardQ, c61GoldilocksP, goldilocksP]

/-- One amended chain combines a 75-bit public PCS allocation with one fresh
Fp2 MAC zero-opening event. -/
def c61AuthenticatedWhirOneChainError : ℚ :=
  (1 : ℚ) / 2 ^ 75 + 1 / c61Fp2CardQ

theorem c61_authenticated_whir_one_chain_error_nonneg :
    0 ≤ c61AuthenticatedWhirOneChainError := by
  norm_num [c61AuthenticatedWhirOneChainError, c61Fp2CardQ,
    c61GoldilocksP, goldilocksP]

/-- Raising the public allocation from 74 to 75 bits absorbs the new MAC
event while retaining a strict 74-bit bound for one authenticated chain. -/
theorem c61_authenticated_whir_one_chain_error_lt_two_pow_neg_74 :
    c61AuthenticatedWhirOneChainError < (1 : ℚ) / 2 ^ 74 := by
  norm_num [c61AuthenticatedWhirOneChainError, c61Fp2CardQ,
    c61GoldilocksP, goldilocksP]

/-- Two independently separated amended chains still fit the existing
per-component `2^-148` native-backend contract. -/
theorem c61_authenticated_whir_two_chain_error_lt_two_pow_neg_148 :
    c61AuthenticatedWhirOneChainError ^ 2 < (1 : ℚ) / 2 ^ 148 := by
  have hnonneg := c61_authenticated_whir_one_chain_error_nonneg
  have hbound := c61_authenticated_whir_one_chain_error_lt_two_pow_neg_74
  nlinarith

def c61RetainedWrapperPcsOneError : ℚ :=
  72 * ((9 : ℚ) / 16) ^ 86
    + (72 * ((2 ^ 28 - 1) + (2 ^ 19 - 1)) : ℚ) / c61Fp2CardQ

/-- Exact retained `C6LNK2` wrapper union used by the executable budget. -/
def c61RetainedWrapperError : ℚ :=
  c61RetainedWrapperPcsOneError ^ 2
    + (2 ^ 16 : ℚ) / c61Fp2CardQ ^ 2
    + (2 ^ 64 : ℚ) / c61Fp2CardQ ^ 2
    + (131_072 : ℚ) / c61Fp2CardQ ^ 2

/-- Concrete native PCS security is a backend contract, not a new Lean
axiom.  Each field is the failure probability after its two independent
74-bit chains have both accepted. -/
structure C61NativeBackendContract where
  modelError : ℚ
  embeddingError : ℚ
  compilerError : ℚ
  model_nonneg : 0 ≤ modelError
  embedding_nonneg : 0 ≤ embeddingError
  compiler_nonneg : 0 ≤ compilerError
  model_bound : modelError ≤ (1 : ℚ) / 2 ^ 148
  embedding_bound : embeddingError ≤ (1 : ℚ) / 2 ^ 148
  compiler_bound : compilerError ≤ (1 : ℚ) / 2 ^ 148

def C61NativeBackendContract.unionError
    (contract : C61NativeBackendContract) : ℚ :=
  contract.modelError + contract.embeddingError + contract.compilerError

theorem c61_native_backend_union_error_le
    (contract : C61NativeBackendContract) :
    contract.unionError ≤ (3 : ℚ) / 2 ^ 148 := by
  unfold C61NativeBackendContract.unionError
  linarith [contract.model_bound, contract.embedding_bound,
    contract.compiler_bound]

/-- Exact Gate-2 rational sum: equality schedules, two runtime fingerprints,
terminal output batching, sparse adjoint, three dual native chains and the
retained designated wrapper. -/
def c61CompleteCertificateError : ℚ :=
  (234 : ℚ) / c61Fp2CardQ
    + (576 : ℚ) / c61Fp2CardQ ^ 2
    + (63 : ℚ) / c61Fp2CardQ
    + (25 : ℚ) / c61Fp2CardQ
    + (3 : ℚ) / 2 ^ 148
    + c61RetainedWrapperError

def c61CertificateErrorUnderContract
    (contract : C61NativeBackendContract) : ℚ :=
  (234 : ℚ) / c61Fp2CardQ
    + (576 : ℚ) / c61Fp2CardQ ^ 2
    + (63 : ℚ) / c61Fp2CardQ
    + (25 : ℚ) / c61Fp2CardQ
    + contract.unionError
    + c61RetainedWrapperError

theorem c61_contract_error_le_registered
    (contract : C61NativeBackendContract) :
    c61CertificateErrorUnderContract contract
      ≤ c61CompleteCertificateError := by
  unfold c61CertificateErrorUnderContract c61CompleteCertificateError
  linarith [c61_native_backend_union_error_le contract]

theorem c61_retained_wrapper_error_lt_two_pow_neg_130 :
    c61RetainedWrapperError < (1 : ℚ) / 2 ^ 130 := by
  norm_num [c61RetainedWrapperError, c61RetainedWrapperPcsOneError,
    c61Fp2CardQ, c61GoldilocksP, goldilocksP]

/-- The exact rational sum is below `2^-119`, a stronger machine-checked
statement than the registered 78.809-bit per-certificate floor. -/
theorem c61_complete_error_lt_two_pow_neg_119 :
    c61CompleteCertificateError < (1 : ℚ) / 2 ^ 119 := by
  norm_num [c61CompleteCertificateError, c61RetainedWrapperError,
    c61RetainedWrapperPcsOneError, c61Fp2CardQ, c61GoldilocksP,
    goldilocksP]

theorem c61_complete_error_meets_literal_79_bits :
    c61CompleteCertificateError < (1 : ℚ) / 2 ^ 79 := by
  exact c61_complete_error_lt_two_pow_neg_119.trans (by norm_num)

/-- Informational session composition: 17 distinct certificates remain below
`2^-115`; this does not weaken the per-certificate statement. -/
theorem c61_seventeen_certificate_error_lt_two_pow_neg_115 :
    17 * c61CompleteCertificateError < (1 : ℚ) / 2 ^ 115 := by
  norm_num [c61CompleteCertificateError, c61RetainedWrapperError,
    c61RetainedWrapperPcsOneError, c61Fp2CardQ, c61GoldilocksP,
    goldilocksP]

end VoltaZk

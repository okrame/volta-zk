import VoltaZk.C6DeltaResidual
import VoltaZk.Prod
import VoltaZk.ProdSound

/-!
# C6 base-share binding and QuickSilver product closure

The C6 residual accumulator is affine only after the production verifier's
unique nonlinear key operation has been discharged.  This file makes that
seam explicit without changing the frozen M7/M8 theorems.

* A provider correlation share is `(r,m)` while the client retains
  `k₀ = m + Δ*r`.
* A hidden correction `d` creates `x = r+d` and corrected key
  `k = k₀ + Δ*d = m + Δ*x`.
* One independent-vector RLC binds committed provider shares to the actual
  client base-key leaves.  For a fixed connection key, a nonzero mismatch
  vector collapses for at most a `1/|F|` fraction of challenge vectors.
* A `ProductClosure` proves the existing scalar-`χ` QuickSilver quantities
  `Q`, `M0` and `M1`.  The exact key polynomial is
  `M0 + M1*Δ + Q*Δ²`; once `Q=0`, no key multiplication enters C6's affine
  residual.

The scalar-`χ` collapse theorem below is the existing M8 product event, not a
new C6 statistical event.
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F]

/-- Provider-visible half of one base full-field correlation. -/
structure C6CorrelationShare (F : Type*) where
  /-- Correlation plaintext. -/
  r : F
  /-- Correlation MAC tag. -/
  m : F

namespace C6CorrelationShare

/-- Pair ordering used by `keyOf`: `(plaintext, tag)`. -/
def pair (share : C6CorrelationShare F) : F × F := (share.r, share.m)

/-- The verifier-only key paired with a provider correlation share. -/
def baseKey (Δ : F) (share : C6CorrelationShare F) : F :=
  keyOf Δ share.pair

/-- The uncorrected correlation as an authenticated value.  Product masks use
this exact form and therefore have no correction. -/
def authed (Δ : F) (share : C6CorrelationShare F) : Authed F :=
  ⟨share.r, share.m, share.baseKey Δ⟩

@[simp] theorem authed_x (Δ : F) (share : C6CorrelationShare F) :
    (share.authed Δ).x = share.r := rfl

@[simp] theorem authed_m (Δ : F) (share : C6CorrelationShare F) :
    (share.authed Δ).m = share.m := rfl

@[simp] theorem authed_k (Δ : F) (share : C6CorrelationShare F) :
    (share.authed Δ).k = share.baseKey Δ := rfl

/-- Every uncorrected product mask is a valid authenticated value. -/
theorem authed_valid (Δ : F) (share : C6CorrelationShare F) :
    (share.authed Δ).Valid Δ := by
  rfl

end C6CorrelationShare

/-- A direct authenticated source whose transfer correction is hidden by C6. -/
structure C6CorrectedSource (F : Type*) where
  /-- One canonical base correlation. -/
  base : C6CorrelationShare F
  /-- Hidden transfer correction. -/
  d : F

namespace C6CorrectedSource

/-- Corrected prover plaintext. -/
def x (source : C6CorrectedSource F) : F := source.base.r + source.d

/-- Client corrected key, computed conceptually from the retained base key and
the hidden correction. -/
def correctedKey (Δ : F) (source : C6CorrectedSource F) : F :=
  source.base.baseKey Δ + Δ * source.d

/-- Corrected authenticated value used for the algebraic seam. -/
def authed (Δ : F) (source : C6CorrectedSource F) : Authed F :=
  ⟨source.x, source.base.m, source.correctedKey Δ⟩

/-- Applying a correction yields exactly `m + Δ*x`. -/
theorem correctedKey_eq (Δ : F) (source : C6CorrectedSource F) :
    source.correctedKey Δ = source.base.m + Δ * source.x := by
  unfold correctedKey C6CorrelationShare.baseKey C6CorrelationShare.pair x keyOf
  ring

/-- A corrected source satisfies the ordinary MAC invariant. -/
theorem authed_valid (Δ : F) (source : C6CorrectedSource F) :
    (source.authed Δ).Valid Δ := by
  unfold authed Authed.Valid
  exact source.correctedKey_eq Δ

end C6CorrectedSource

/-- Client-side RLC of the actual verifier-only base-key leaves. -/
def c6BaseKeyRlc {T : ℕ} (alpha key : Fin T → F) : F :=
  ∑ i, alpha i * key i

/-- Provider-side RLC of committed correlation plaintext shares. -/
def c6BasePlaintextRlc {T : ℕ} (alpha : Fin T → F)
    (share : Fin T → C6CorrelationShare F) : F :=
  ∑ i, alpha i * (share i).r

/-- Provider-side RLC of committed correlation tags. -/
def c6BaseTagRlc {T : ℕ} (alpha : Fin T → F)
    (share : Fin T → C6CorrelationShare F) : F :=
  ∑ i, alpha i * (share i).m

/-- The designated verifier's base-share binding equation. -/
def C6BaseShareAccept {T : ℕ} (Δ : F) (alpha key : Fin T → F)
    (share : Fin T → C6CorrelationShare F) : Prop :=
  c6BaseKeyRlc alpha key
      + Δ * (-c6BasePlaintextRlc alpha share)
    = c6BaseTagRlc alpha share

/-- The binding residual is exactly the RLC of pointwise key/share errors. -/
theorem c6_base_share_error_rlc {T : ℕ} (Δ : F) (alpha key : Fin T → F)
    (share : Fin T → C6CorrelationShare F) :
    (∑ i, alpha i * (key i - (share i).baseKey Δ))
      = c6BaseKeyRlc alpha key
          + Δ * (-c6BasePlaintextRlc alpha share)
          - c6BaseTagRlc alpha share := by
  calc
    (∑ i, alpha i * (key i - (share i).baseKey Δ))
        = ∑ i, (alpha i * key i - Δ * (alpha i * (share i).r)
            - alpha i * (share i).m) := by
          apply Finset.sum_congr rfl
          intro i _
          unfold C6CorrelationShare.baseKey C6CorrelationShare.pair keyOf
          ring
    _ = c6BaseKeyRlc alpha key
          + Δ * (-c6BasePlaintextRlc alpha share)
          - c6BaseTagRlc alpha share := by
        unfold c6BaseKeyRlc c6BasePlaintextRlc c6BaseTagRlc
        rw [Finset.sum_sub_distrib, Finset.sum_sub_distrib, ← Finset.mul_sum]
        ring

/-- Acceptance is equivalently a zero RLC of the pointwise binding errors. -/
theorem c6_base_share_accept_iff {T : ℕ} (Δ : F) (alpha key : Fin T → F)
    (share : Fin T → C6CorrelationShare F) :
    C6BaseShareAccept Δ alpha key share
      ↔ ∑ i, alpha i * (key i - (share i).baseKey Δ) = 0 := by
  unfold C6BaseShareAccept
  rw [← sub_eq_zero]
  rw [← c6_base_share_error_rlc]

/-- Perfect completeness of the base-share RLC. -/
theorem c6_base_share_binding_complete {T : ℕ} (Δ : F)
    (alpha key : Fin T → F) (share : Fin T → C6CorrelationShare F)
    (hkey : ∀ i, key i = (share i).baseKey Δ) :
    C6BaseShareAccept Δ alpha key share := by
  rw [c6_base_share_accept_iff]
  apply Finset.sum_eq_zero
  intro i _
  rw [hkey i, sub_self, mul_zero]

variable [Fintype F]

/-- Accepting independent-vector challenges, packaged noncomputably so the
statement does not depend on a particular decision procedure for `Prop`. -/
noncomputable def c6BaseShareAcceptingVectors {T : ℕ} (Δ : F)
    (key : Fin T → F) (share : Fin T → C6CorrelationShare F) :
    Finset (Fin T → F) := by
  classical
  exact univ.filter fun alpha => C6BaseShareAccept Δ alpha key share

/-- **Independent-vector base-share binding.**  For a fixed connection key,
if at least one actual verifier leaf differs from the committed provider
share, at most `|F|^(T-1)` of the `|F|^T` RLC vectors accept.  There is no
second root count over `Δ`: for this connection, a pointwise equality is
already a valid authenticated share. -/
theorem c6_base_share_binding_sound {T : ℕ} (Δ : F) (key : Fin T → F)
    (share : Fin T → C6CorrelationShare F) {j₀ : Fin T}
    (hbad : key j₀ ≠ (share j₀).baseKey Δ) :
    (c6BaseShareAcceptingVectors Δ key share).card
      ≤ Fintype.card F ^ (T - 1) := by
  classical
  unfold c6BaseShareAcceptingVectors
  refine le_trans
    (le_of_eq (congrArg Finset.card
      (Finset.filter_congr fun alpha _ => c6_base_share_accept_iff Δ alpha key share)))
    (card_linearForm_zero_le
      (fun i => key i - (share i).baseKey Δ) (sub_ne_zero.mpr hbad))

variable {F : Type*} [Field F]

/-- Convert one authenticated triple to the frozen M8 plaintext/tag shape. -/
def c6ProductClaim (a b c : Authed F) : ProdClaim F :=
  ⟨(a.x, a.m), (b.x, b.m), (c.x, c.m)⟩

/-- Exact Rust weight for product claim `j`. -/
def c6ProductWeight {T : ℕ} (chi : F) (j : Fin T) : F :=
  chi ^ (j.val + 1)

/-- Quadratic coefficient of one complete QuickSilver batch. -/
def c6ProductQ {T : ℕ} (a b c : Fin T → Authed F) (chi : F) : F :=
  ∑ j, c6ProductWeight chi j * prodQ (c6ProductClaim (a j) (b j) (c j))

/-- Exact constant message coefficient, including the full-correlation mask. -/
def c6ProductM0 {T : ℕ} (a b c : Fin T → Authed F) (mask : Authed F)
    (chi : F) : F :=
  (∑ j, c6ProductWeight chi j * prodA0 (c6ProductClaim (a j) (b j) (c j)))
    + mask.m

/-- Exact linear message coefficient, including the full-correlation mask. -/
def c6ProductM1 {T : ℕ} (a b c : Fin T → Authed F) (mask : Authed F)
    (chi : F) : F :=
  (∑ j, c6ProductWeight chi j * prodA1 (c6ProductClaim (a j) (b j) (c j)))
    + mask.x

/-- The old production verifier's nonlinear key side. -/
def c6ProductKeySide {T : ℕ} (Δ : F) (a b c : Fin T → Authed F)
    (mask : Authed F) (chi : F) : F :=
  (∑ j, c6ProductWeight chi j * ((a j).k * (b j).k - Δ * (c j).k))
    + mask.k

/-- Valid authenticated inputs make the old key term equal the frozen
`ProdClaim` key polynomial. -/
theorem c6_product_key_matches_prodKey (Δ : F) (a b c : Authed F)
    (ha : a.Valid Δ) (hb : b.Valid Δ) (hc : c.Valid Δ) :
    a.k * b.k - Δ * c.k = prodKey Δ (c6ProductClaim a b c) := by
  unfold Authed.Valid at ha hb hc
  rw [ha, hb, hc]
  rfl

/-- **Exact product-polynomial expansion.**  This is the obstruction that
prevents treating `prod_batch_verify` as a linear-key DAG node. -/
theorem c6_product_polynomial_expand {T : ℕ} (Δ : F)
    (a b c : Fin T → Authed F) (mask : Authed F) (chi : F)
    (ha : ∀ j, (a j).Valid Δ) (hb : ∀ j, (b j).Valid Δ)
    (hc : ∀ j, (c j).Valid Δ) (hmask : mask.Valid Δ) :
    c6ProductKeySide Δ a b c mask chi
      = c6ProductM0 a b c mask chi
        + c6ProductM1 a b c mask chi * Δ
        + c6ProductQ a b c chi * (Δ * Δ) := by
  have hexpand := prodKey_rlc_expand
    (fun j => c6ProductClaim (a j) (b j) (c j))
    (mask.x, mask.m) Δ (fun j => c6ProductWeight chi j)
  calc
    c6ProductKeySide Δ a b c mask chi
        = (∑ j, c6ProductWeight chi j
              * prodKey Δ (c6ProductClaim (a j) (b j) (c j)))
            + keyOf Δ (mask.x, mask.m) := by
          have hsum :
              (∑ j, c6ProductWeight chi j
                * ((a j).k * (b j).k - Δ * (c j).k))
                = ∑ j, c6ProductWeight chi j
                  * prodKey Δ (c6ProductClaim (a j) (b j) (c j)) := by
            apply Finset.sum_congr rfl
            intro j _
            rw [c6_product_key_matches_prodKey Δ (a j) (b j) (c j)
              (ha j) (hb j) (hc j)]
          unfold c6ProductKeySide
          rw [hsum]
          unfold Authed.Valid at hmask
          rw [hmask]
          rfl
    _ = ((∑ j, c6ProductWeight chi j
              * prodA0 (c6ProductClaim (a j) (b j) (c j))) + mask.m)
          + ((∑ j, c6ProductWeight chi j
              * prodA1 (c6ProductClaim (a j) (b j) (c j))) + mask.x) * Δ
          + (∑ j, c6ProductWeight chi j
              * prodQ (c6ProductClaim (a j) (b j) (c j))) * (Δ * Δ) := hexpand
    _ = c6ProductM0 a b c mask chi
          + c6ProductM1 a b c mask chi * Δ
          + c6ProductQ a b c chi * (Δ * Δ) := rfl

/-- **C6 `ProductClosure`.**  Once the wrapper proves the existing
QuickSilver quadratic coefficient is zero, the old nonlinear verifier check
is an affine consequence for every `Δ`. -/
theorem c6_product_closure {T : ℕ} (Δ : F)
    (a b c : Fin T → Authed F) (mask : Authed F) (chi : F)
    (ha : ∀ j, (a j).Valid Δ) (hb : ∀ j, (b j).Valid Δ)
    (hc : ∀ j, (c j).Valid Δ) (hmask : mask.Valid Δ)
    (hq : c6ProductQ a b c chi = 0) :
    c6ProductKeySide Δ a b c mask chi
      = c6ProductM0 a b c mask chi + c6ProductM1 a b c mask chi * Δ := by
  rw [c6_product_polynomial_expand Δ a b c mask chi ha hb hc hmask, hq]
  ring

/-- Pointwise true products imply the wrapper's batched `Q=0` relation. -/
theorem c6_product_true_implies_q_zero {T : ℕ}
    (a b c : Fin T → Authed F) (chi : F)
    (hproduct : ∀ j, (c j).x = (a j).x * (b j).x) :
    c6ProductQ a b c chi = 0 := by
  unfold c6ProductQ c6ProductClaim prodQ
  apply Finset.sum_eq_zero
  intro j _
  rw [hproduct j]
  ring

variable [Fintype F] [DecidableEq F]

/-- The wrapper's `Q=0` check reuses the exact scalar-`χ` M8 collapse event.
It does not create another C6 event. -/
theorem c6_product_q_collapse_sound {T : ℕ}
    (a b c : Fin T → Authed F) {j₀ : Fin T}
    (hbad : (c j₀).x ≠ (a j₀).x * (b j₀).x) :
    (univ.filter fun chi : F => c6ProductQ a b c chi = 0).card ≤ T := by
  simpa [c6ProductQ, c6ProductWeight, c6ProductClaim, prodQ] using
    (card_scalarRlc_zero_le
      (fun j => (a j).x * (b j).x - (c j).x)
      (sub_ne_zero.mpr (Ne.symm hbad)))

variable {F : Type*} [Field F]

/-- Composition for direct corrected sources and an uncorrected product mask.
This is the formal boundary consumed by the typed C6 IR. -/
theorem c6_corrected_source_product_closure {T : ℕ} (Δ : F)
    (a b c : Fin T → C6CorrectedSource F) (mask : C6CorrelationShare F)
    (chi : F)
    (hq : c6ProductQ
      (fun j => (a j).authed Δ)
      (fun j => (b j).authed Δ)
      (fun j => (c j).authed Δ) chi = 0) :
    c6ProductKeySide Δ
        (fun j => (a j).authed Δ)
        (fun j => (b j).authed Δ)
        (fun j => (c j).authed Δ) (mask.authed Δ) chi
      = c6ProductM0
          (fun j => (a j).authed Δ)
          (fun j => (b j).authed Δ)
          (fun j => (c j).authed Δ) (mask.authed Δ) chi
        + c6ProductM1
            (fun j => (a j).authed Δ)
            (fun j => (b j).authed Δ)
            (fun j => (c j).authed Δ) (mask.authed Δ) chi * Δ := by
  exact c6_product_closure Δ
    (fun j => (a j).authed Δ)
    (fun j => (b j).authed Δ)
    (fun j => (c j).authed Δ) (mask.authed Δ) chi
    (fun j => (a j).authed_valid Δ)
    (fun j => (b j).authed_valid Δ)
    (fun j => (c j).authed_valid Δ)
    (mask.authed_valid Δ) hq

end VoltaZk

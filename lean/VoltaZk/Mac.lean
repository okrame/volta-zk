import Mathlib.Algebra.Field.Basic
import Mathlib.Algebra.BigOperators.Group.Finset.Defs
import Mathlib.Data.Fintype.Basic
import Mathlib.Tactic.Ring

/-!
# VOLE-style MAC-authenticated values

`docs/protocol-sketch.md` § "Minimal Authenticated Value Interface".

The prover holds `(x, m)`, the designated verifier holds `k`, and the session
key `Δ` ties them together through the MAC invariant `k = m + Δ·x`.

For this first formal target we work over a single finite field `F`, playing
the role of the extension field `E` of the protocol. The subfield refinement
(16-bit corrections living in `F_p ⊆ E`) is deferred; see `VoltaZk.Ideal`.
-/

namespace VoltaZk

/-- An authenticated value. The record packages both parties' shares for
reasoning purposes; *who knows what* is tracked by the protocol and simulator
definitions (the simulator may only read `k`, never `x` or `m`). -/
@[ext]
structure Authed (F : Type*) where
  /-- plaintext value (prover side) -/
  x : F
  /-- MAC tag (prover side) -/
  m : F
  /-- MAC key (verifier side) -/
  k : F

namespace Authed

variable {F : Type*} [Field F]

/-- The MAC invariant `k = m + Δ·x` for session key `Δ`. -/
def Valid (Δ : F) (a : Authed F) : Prop :=
  a.k = a.m + Δ * a.x

instance : Add (Authed F) :=
  ⟨fun a b => ⟨a.x + b.x, a.m + b.m, a.k + b.k⟩⟩

instance : Zero (Authed F) :=
  ⟨⟨0, 0, 0⟩⟩

instance : Neg (Authed F) :=
  ⟨fun a => ⟨-a.x, -a.m, -a.k⟩⟩

instance : Sub (Authed F) :=
  ⟨fun a b => ⟨a.x - b.x, a.m - b.m, a.k - b.k⟩⟩

instance : AddCommGroup (Authed F) where
  add := (· + ·)
  zero := 0
  add_assoc a b c := by ext <;> apply add_assoc
  zero_add a := by ext <;> apply zero_add
  add_zero a := by ext <;> apply add_zero
  add_comm a b := by ext <;> apply add_comm
  neg_add_cancel a := by ext <;> apply neg_add_cancel
  sub_eq_add_neg a b := by ext <;> apply sub_eq_add_neg
  nsmul := nsmulRec
  zsmul := zsmulRec

/-- Scaling by a public field element: both parties scale locally. -/
instance : SMul F (Authed F) :=
  ⟨fun c a => ⟨c * a.x, c * a.m, c * a.k⟩⟩

@[simp] lemma add_x (a b : Authed F) : (a + b).x = a.x + b.x := rfl
@[simp] lemma add_m (a b : Authed F) : (a + b).m = a.m + b.m := rfl
@[simp] lemma add_k (a b : Authed F) : (a + b).k = a.k + b.k := rfl
@[simp] lemma zero_x : (0 : Authed F).x = 0 := rfl
@[simp] lemma zero_m : (0 : Authed F).m = 0 := rfl
@[simp] lemma zero_k : (0 : Authed F).k = 0 := rfl
@[simp] lemma smul_x (c : F) (a : Authed F) : (c • a).x = c * a.x := rfl
@[simp] lemma smul_m (c : F) (a : Authed F) : (c • a).m = c * a.m := rfl
@[simp] lemma smul_k (c : F) (a : Authed F) : (c • a).k = c * a.k := rfl
@[simp] lemma neg_x (a : Authed F) : (-a).x = -a.x := rfl
@[simp] lemma neg_m (a : Authed F) : (-a).m = -a.m := rfl
@[simp] lemma neg_k (a : Authed F) : (-a).k = -a.k := rfl
@[simp] lemma sub_x (a b : Authed F) : (a - b).x = a.x - b.x := rfl
@[simp] lemma sub_m (a b : Authed F) : (a - b).m = a.m - b.m := rfl
@[simp] lemma sub_k (a b : Authed F) : (a - b).k = a.k - b.k := rfl

/-- Plaintext projection as an additive map. -/
def xHom : Authed F →+ F where
  toFun := x
  map_zero' := rfl
  map_add' _ _ := rfl

/-- Tag projection as an additive map. -/
def mHom : Authed F →+ F where
  toFun := m
  map_zero' := rfl
  map_add' _ _ := rfl

/-- Key projection as an additive map. -/
def kHom : Authed F →+ F where
  toFun := k
  map_zero' := rfl
  map_add' _ _ := rfl

@[simp] lemma sum_x {ι : Type*} (s : Finset ι) (f : ι → Authed F) :
    (∑ i ∈ s, f i).x = ∑ i ∈ s, (f i).x :=
  map_sum xHom f s

@[simp] lemma sum_m {ι : Type*} (s : Finset ι) (f : ι → Authed F) :
    (∑ i ∈ s, f i).m = ∑ i ∈ s, (f i).m :=
  map_sum mHom f s

@[simp] lemma sum_k {ι : Type*} (s : Finset ι) (f : ι → Authed F) :
    (∑ i ∈ s, f i).k = ∑ i ∈ s, (f i).k :=
  map_sum kHom f s

theorem Valid.zero (Δ : F) : (0 : Authed F).Valid Δ := by
  simp [Valid]

/-- Linearity of the MAC: sums of valid values are valid (both parties add
their shares locally, no communication). -/
theorem Valid.add {Δ : F} {a b : Authed F} (ha : a.Valid Δ) (hb : b.Valid Δ) :
    (a + b).Valid Δ := by
  unfold Valid at *
  simp only [add_x, add_m, add_k, ha, hb]
  ring

/-- Linearity of the MAC: public scalings of valid values are valid. -/
theorem Valid.smul {Δ : F} {a : Authed F} (ha : a.Valid Δ) (c : F) :
    (c • a).Valid Δ := by
  unfold Valid at *
  simp only [smul_x, smul_m, smul_k, ha]
  ring

/-- Linearity of the MAC: negations of valid values are valid. -/
theorem Valid.neg {Δ : F} {a : Authed F} (ha : a.Valid Δ) : (-a).Valid Δ := by
  unfold Valid at *
  simp only [neg_x, neg_m, neg_k, ha]
  ring

/-- Linearity of the MAC: differences of valid values are valid. -/
theorem Valid.sub {Δ : F} {a b : Authed F} (ha : a.Valid Δ) (hb : b.Valid Δ) :
    (a - b).Valid Δ := by
  unfold Valid at *
  simp only [sub_x, sub_m, sub_k, ha, hb]
  ring

theorem Valid.sum {Δ : F} {ι : Type*} {s : Finset ι} {f : ι → Authed F}
    (h : ∀ i ∈ s, (f i).Valid Δ) : (∑ i ∈ s, f i).Valid Δ :=
  Finset.sum_induction f (Valid Δ) (fun _ _ => Valid.add) (Valid.zero Δ) h

/-- Embedding of a public constant `c`: both parties form it locally
(`x = c`, `m = 0`, `k = Δ·c`), and the invariant holds by construction. -/
def ofPublic (Δ c : F) : Authed F := ⟨c, 0, Δ * c⟩

@[simp] lemma ofPublic_x (Δ c : F) : (ofPublic Δ c).x = c := rfl
@[simp] lemma ofPublic_m (Δ c : F) : (ofPublic Δ c).m = 0 := rfl
@[simp] lemma ofPublic_k (Δ c : F) : (ofPublic Δ c).k = Δ * c := rfl

theorem ofPublic_valid (Δ c : F) : (ofPublic Δ c).Valid Δ := by
  simp [Valid, ofPublic]

end Authed

end VoltaZk

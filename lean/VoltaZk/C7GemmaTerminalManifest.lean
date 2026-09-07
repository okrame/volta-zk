import VoltaZk.C7StackedWeightUse
import Mathlib.Tactic

/-!
# Exact Gemma-31B terminal declaration

Rust and Lean read the same canonical source file.  This file proves that the
declared 480 logical slots refine the frozen stacked-use profile.  It does not
claim that the runtime model compiler emits this declaration.
-/

namespace VoltaZk

open Finset Matrix

inductive C7GemmaTerminalPlane
  | weight
  /-- Protocol plane B; no model-level meaning is assigned here. -/
  | planeB
  | kvOld
  | kvNew
  deriving DecidableEq, Repr

structure C7GemmaTerminalSpec where
  plane : C7GemmaTerminalPlane
  owner : String
  /-- Private tensor owners. -/
  privateSourceKeys : List String
  /-- Public inventory dependencies only; not private W/norm contents. -/
  publicSourceKeys : List String
  deriving DecidableEq, Repr

structure C7GemmaTerminalRecord extends C7GemmaTerminalSpec where
  ordinal : Nat
  useAxisLength : Nat
  deriving DecidableEq, Repr

def c7GemmaLocalMatrixRoles : List String :=
  ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

def c7GemmaGlobalMatrixRoles : List String :=
  ["q_proj", "k_eq_v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

def c7GemmaNormSourceRoles : List String :=
  ["input_layernorm.weight", "post_attention_layernorm.weight",
   "post_feedforward_layernorm.weight", "pre_feedforward_layernorm.weight",
   "self_attn.k_norm.weight", "self_attn.q_norm.weight"]

/-! ## Ragged six-role norm bundle

Gemma's four RMS vectors and its q/k norm vectors do not share one coordinate
type.  Consequently, the older uniform-`D` theorem is not an exact Gemma
instantiation.  The sigma index below retains each role's own dimension. -/

def c7GemmaRaggedNormDiagonal
    {F : Type*} [Zero F] {D : Fin 6 → Type*}
    [∀ role, DecidableEq (D role)]
    (activation : Fin 2 → ∀ role, D role → F) :
    Matrix (Fin 2 × Sigma D) (Sigma D) F :=
  fun tagged physical =>
    if tagged.2 = physical then
      activation tagged.1 tagged.2.1 tagged.2.2
    else 0

theorem c7_gemma_ragged_norm_diagonal_mulVec
    {F : Type*} [Semiring F] {D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation : Fin 2 → ∀ role, D role → F)
    (weight : ∀ role, D role → F)
    (phase : Fin 2) (role : Fin 6) (d : D role) :
    (c7GemmaRaggedNormDiagonal activation *ᵥ
      (fun rd => weight rd.1 rd.2)) (phase, ⟨role, d⟩) =
        activation phase role d * weight role d := by
  classical
  simp [c7GemmaRaggedNormDiagonal, Matrix.mulVec, dotProduct]

def C7GemmaRaggedNormPerUseRelation
    {F : Type*} [Mul F] {D : Fin 6 → Type*}
    (activation output : Fin 2 → ∀ role, D role → F)
    (weight : ∀ role, D role → F) : Prop :=
  ∀ phase role d,
    output phase role d = activation phase role d * weight role d

def C7GemmaRaggedNormBundleRelation
    {F : Type*} [Semiring F] {D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation output : Fin 2 → ∀ role, D role → F)
    (weight : ∀ role, D role → F) : Prop :=
  (c7GemmaRaggedNormDiagonal activation *ᵥ
      (fun rd => weight rd.1 rd.2)) =
    fun tagged => output tagged.1 tagged.2.1 tagged.2.2

/-- One sigma-indexed bundle is exactly the twelve phase/role equations even
when the six physical vectors have different lengths. -/
theorem c7_gemma_ragged_norm_bundle_iff_per_use
    {F : Type*} [Semiring F] {D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation output : Fin 2 → ∀ role, D role → F)
    (weight : ∀ role, D role → F) :
    C7GemmaRaggedNormBundleRelation activation output weight ↔
      C7GemmaRaggedNormPerUseRelation activation output weight := by
  constructor
  · intro h phase role d
    have hrow := congrFun h (phase, ⟨role, d⟩)
    rw [c7_gemma_ragged_norm_diagonal_mulVec] at hrow
    exact hrow.symm
  · intro h
    funext tagged
    rcases tagged with ⟨phase, ⟨role, d⟩⟩
    rw [c7_gemma_ragged_norm_diagonal_mulVec]
    exact (h phase role d).symm

/-- A row for one sigma-tagged role/coordinate cannot read any other one. -/
theorem c7_gemma_ragged_norm_no_cross_term
    {F : Type*} [Zero F] {D : Fin 6 → Type*}
    [∀ role, DecidableEq (D role)]
    (activation : Fin 2 → ∀ role, D role → F)
    (phase : Fin 2) (owned other : Sigma D) (h : owned ≠ other) :
    c7GemmaRaggedNormDiagonal activation (phase, owned) other = 0 := by
  simp [c7GemmaRaggedNormDiagonal, h]

def c7GemmaLocalNormDimension (role : Fin 6) : Nat :=
  if role.val < 4 then 5376 else 256

def c7GemmaGlobalNormDimension (role : Fin 6) : Nat :=
  if role.val < 4 then 5376 else 512

abbrev C7GemmaLocalNormCoordinate (role : Fin 6) : Type :=
  Fin (c7GemmaLocalNormDimension role)

abbrev C7GemmaGlobalNormCoordinate (role : Fin 6) : Type :=
  Fin (c7GemmaGlobalNormDimension role)

theorem c7_gemma_local_ragged_norm_bundle_iff_per_use
    {F : Type*} [Semiring F]
    (activation output :
      Fin 2 → ∀ role, C7GemmaLocalNormCoordinate role → F)
    (weight : ∀ role, C7GemmaLocalNormCoordinate role → F) :
    C7GemmaRaggedNormBundleRelation activation output weight ↔
      C7GemmaRaggedNormPerUseRelation activation output weight :=
  c7_gemma_ragged_norm_bundle_iff_per_use activation output weight

theorem c7_gemma_global_ragged_norm_bundle_iff_per_use
    {F : Type*} [Semiring F]
    (activation output :
      Fin 2 → ∀ role, C7GemmaGlobalNormCoordinate role → F)
    (weight : ∀ role, C7GemmaGlobalNormCoordinate role → F) :
    C7GemmaRaggedNormBundleRelation activation output weight ↔
      C7GemmaRaggedNormPerUseRelation activation output weight :=
  c7_gemma_ragged_norm_bundle_iff_per_use activation output weight

theorem c7_gemma_ragged_norm_dimension_census :
    (∑ role : Fin 6, c7GemmaLocalNormDimension role) = 22016 ∧
    (∑ role : Fin 6, c7GemmaGlobalNormDimension role) = 22528 := by
  decide

theorem c7_gemma_ragged_norm_sigma_card_census :
    Fintype.card (Sigma C7GemmaLocalNormCoordinate) = 22016 ∧
    Fintype.card (Sigma C7GemmaGlobalNormCoordinate) = 22528 := by
  simpa only [Fintype.card_sigma, Fintype.card_fin] using
    c7_gemma_ragged_norm_dimension_census

def c7GemmaMatrixSourceKey (layer : Nat) (role : String) : String :=
  let suffix :=
    match role with
    | "q_proj" => "self_attn.q_proj.weight"
    | "k_proj" => "self_attn.k_proj.weight"
    | "k_eq_v_proj" => "self_attn.k_proj.weight"
    | "v_proj" => "self_attn.v_proj.weight"
    | "o_proj" => "self_attn.o_proj.weight"
    | "gate_proj" => "mlp.gate_proj.weight"
    | "up_proj" => "mlp.up_proj.weight"
    | "down_proj" => "mlp.down_proj.weight"
    | _ => "INVALID"
  s!"model.language_model.layers.{layer}.{suffix}"

/-- Every sixth model layer is global: 5, 11, ..., 59. -/
def c7GemmaLayerTerminalSpecs (layer : Nat) : List C7GemmaTerminalSpec :=
  let roles :=
    if layer % 6 = 5 then c7GemmaGlobalMatrixRoles else c7GemmaLocalMatrixRoles
  roles.map (fun role =>
      ⟨.weight, s!"weight/layer/{layer}/{role}",
        [c7GemmaMatrixSourceKey layer role], []⟩) ++
    [⟨.weight, s!"weight/layer/{layer}/norm_bundle",
      c7GemmaNormSourceRoles.map
        (fun role => s!"model.language_model.layers.{layer}.{role}"),
      [s!"model.language_model.layers.{layer}.layer_scalar"]⟩]

def c7GemmaWeightTerminalSpecs : List C7GemmaTerminalSpec :=
  (List.range 60).flatMap c7GemmaLayerTerminalSpecs ++
    [⟨.weight, "weight/tied_embedding",
      ["model.language_model.embed_tokens.weight"], []⟩,
     ⟨.weight, "weight/final_norm", ["model.language_model.norm.weight"], []⟩]

def c7GemmaNonWeightTerminalSpecs : List C7GemmaTerminalSpec :=
  (List.range 4).map (fun i => ⟨.planeB, s!"b/{i}", [], []⟩) ++
  (List.range 2).map (fun i => ⟨.kvOld, s!"kv_old/{i}", [], []⟩) ++
  (List.range 2).map (fun i => ⟨.kvNew, s!"kv_new/{i}", [], []⟩)

def c7GemmaTerminalSpecs : List C7GemmaTerminalSpec :=
  c7GemmaWeightTerminalSpecs ++ c7GemmaNonWeightTerminalSpecs

def c7GemmaDeclaredTerminalManifest : List C7GemmaTerminalRecord :=
  c7GemmaTerminalSpecs.zipIdx.map fun specAndOrdinal =>
    { plane := specAndOrdinal.1.plane
      owner := specAndOrdinal.1.owner
      privateSourceKeys := specAndOrdinal.1.privateSourceKeys
      publicSourceKeys := specAndOrdinal.1.publicSourceKeys
      ordinal := specAndOrdinal.2
      useAxisLength := 1 }

def c7GemmaTerminalPlaneCode : C7GemmaTerminalPlane → String
  | .weight => "W"
  | .planeB => "B"
  | .kvOld => "KV_OLD"
  | .kvNew => "KV_NEW"

def c7GemmaTerminalRecordLine (record : C7GemmaTerminalRecord) : String :=
  let renderKeys : List String → String
    | [] => "-"
    | keys => String.intercalate ";" keys
  s!"{record.ordinal},{c7GemmaTerminalPlaneCode record.plane},{record.owner}," ++
    s!"{record.useAxisLength},{renderKeys record.privateSourceKeys}," ++
    s!"{renderKeys record.publicSourceKeys}"

def c7GemmaTerminalManifestHeader : List String :=
  ["@schema=volta-c7-d126-gemma31b-terminal-manifest-v1",
   "@model=google/gemma-4-31B",
   "@revision=5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
   "@config_sha256=6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
   "@model_index_sha256=d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2",
   "@model_shard_1_lfs_sha256=186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
   "@model_shard_1_bytes=49784788364",
   "@model_shard_2_lfs_sha256=b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
   "@model_shard_2_bytes=12761549884",
   "@model_shards_total_bytes=62546338248",
   "@tensor_payload_bytes=62546177752",
   "@safetensors_framing_bytes=160496",
   "@text_only=true",
   "@context_cap=4096",
   "@private_learned_tensor_count=772",
   "@public_layer_scalar_count=60",
   "@forbidden_vision_bridge_tensor_count=356",
   "@physical_tensor_count=1188",
   "@weight_matrix_scalars=30696013824",
   "@weight_norm_scalars=1331456",
   "@weight_private_scalars=30697345280",
   "@packed_i16_bytes=61394690560",
   "@terminal_count=480",
   "@record_columns=ordinal|plane|owner|use_axis_length|private_source_keys|public_source_keys"]

/-- This literal is also consumed by Rust through `include_str!`. -/
def c7GemmaSharedTerminalManifestSource : String :=
  include_str "../../manifests/c7-d126-gemma31b-terminals-v1.csv"

/-- Comparing lines avoids constructing one quadratic-size concatenated
string inside the kernel.  The final empty line freezes the trailing LF. -/
def c7GemmaCanonicalTerminalManifestLines : List String :=
  c7GemmaTerminalManifestHeader ++
    c7GemmaDeclaredTerminalManifest.map c7GemmaTerminalRecordLine ++ [""]

def c7GemmaSharedTerminalManifestLines : List String :=
  c7GemmaSharedTerminalManifestSource.splitOn "\n"

set_option linter.hashCommand false in
#guard c7GemmaSharedTerminalManifestLines ==
  c7GemmaCanonicalTerminalManifestLines

/-- Census/order conditions supplied by the logical declaration to the
existing profile.  This predicate does not connect source values to the 472
heterogeneous algebraic relations emitted by a runtime compiler. -/
def C7GemmaDeclaredManifestRefinesStackedProfile
    (manifest : List C7GemmaTerminalRecord)
    (profile : C7StackedUseProfile) : Prop :=
  profile = c7GemmaStackedUseProfile ∧
  manifest.map (·.ordinal) = List.range profile.allTerminals ∧
  (manifest.filter fun record => record.plane = .weight).length =
    profile.weightTerminals ∧
  (manifest.filter fun record => record.plane = .planeB).length = 4 ∧
  (manifest.filter fun record => record.plane = .kvOld).length = 2 ∧
  (manifest.filter fun record => record.plane = .kvNew).length = 2 ∧
  manifest.map (·.useAxisLength) = profile.useAxisLengths ∧
  (manifest.flatMap (·.privateSourceKeys)).length = 772 ∧
  (manifest.flatMap (·.publicSourceKeys)).length = 60

set_option maxRecDepth 100000 in
set_option maxHeartbeats 0 in
-- The exact 480-record normalization exceeds the default reduction budget.
theorem c7_gemma_declared_terminal_manifest_refines_stacked_profile :
    C7GemmaDeclaredManifestRefinesStackedProfile
      c7GemmaDeclaredTerminalManifest c7GemmaStackedUseProfile := by
  constructor
  · rfl
  · decide

theorem c7_gemma_pinned_weight_source_census :
    50 * 478937088 + 10 * 533987328 + 1409286144 = 30696013824 ∧
    50 * 22016 + 10 * 22528 + 5376 = 1331456 ∧
    30696013824 + 1331456 = 30697345280 ∧
    2 * 30697345280 = 61394690560 := by
  norm_num

set_option maxRecDepth 100000 in
theorem c7_gemma_declared_source_key_census :
    (c7GemmaDeclaredTerminalManifest.flatMap (·.privateSourceKeys)).length = 772 ∧
    (c7GemmaDeclaredTerminalManifest.flatMap (·.publicSourceKeys)).length = 60 := by
  decide

/-- The pinned text-only index partitions all physical tensor keys.  This
count does not bind the values of the 60 public layer scalars. -/
theorem c7_gemma_pinned_source_classification_census :
    772 + 60 + 356 = 1188 := by
  norm_num

theorem c7_gemma_pinned_shard_byte_census :
    49784788364 + 12761549884 = 62546338248 ∧
    62546177752 + 160496 = 62546338248 := by
  norm_num

/-- Exact seam still owed by the runtime model compiler.  No theorem here
asserts this predicate.  It also does not bind the ordered values of the 60
public layer scalars or their use by base GKR, nor instantiate a heterogeneous
family of 472 matrix/norm relations; those require a pinned-value digest and
runtime relation. -/
def C7RuntimeCompilerEmitsDeclaredGemmaManifest
    (runtimeOutput : List C7GemmaTerminalRecord) : Prop :=
  runtimeOutput = c7GemmaDeclaredTerminalManifest

#print axioms c7_gemma_declared_terminal_manifest_refines_stacked_profile
#print axioms c7_gemma_ragged_norm_bundle_iff_per_use
#print axioms c7_gemma_ragged_norm_no_cross_term
#print axioms c7_gemma_local_ragged_norm_bundle_iff_per_use
#print axioms c7_gemma_global_ragged_norm_bundle_iff_per_use
#print axioms c7_gemma_ragged_norm_sigma_card_census
#print axioms c7_gemma_pinned_weight_source_census
#print axioms c7_gemma_declared_source_key_census
#print axioms c7_gemma_pinned_source_classification_census
#print axioms c7_gemma_pinned_shard_byte_census

end VoltaZk

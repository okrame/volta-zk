//! P4 layer-scale layout: the four weight tensors of one GPT-2 transformer
//! layer packed into a single 2^24-coefficient Ligero commitment.
//!
//! A k×n weight tensor W (row-major) is committed as its zero-padded block
//! `W_pad[l * n_pad + j] = W[l * n + j]` (l < k, j < n; zero elsewhere) with
//! `n_pad = n.next_power_of_two()`, `k_pad = k.next_power_of_two()`. The
//! block MLE at a `WeightClaimP`-style point (r_j ‖ r_l) — column vars LSB,
//! `pad_bits(n)` of them, then `pad_bits(k)` row vars — then equals exactly
//! the padded-tensor evaluation the GEMM seam hands outward, so the claim
//! maps 1:1 onto a `BlockClaim` on this commitment.
//!
//! Blocks are placed largest-first at cumulative offsets: block sizes are
//! powers of two in descending order, so every offset is automatically a
//! multiple of the block's own size (the `BlockClaim` / `claim_geom`
//! alignment invariant).

use crate::batch::BlockClaim;
use crate::ligero::LigeroParams;
use volta_field::Fp2;

/// Layer-scale Ligero parameters: 2^24-coefficient message (rows 2^10 ×
/// cols 2^14), same rate ((2^14+512)/2^15 ≈ 0.516), pad and query count as
/// `GPT2_FULL` — only `row_bits` shrinks (13 → 10) for the one-layer vector.
pub const P4_LAYER: LigeroParams =
    LigeroParams { row_bits: 10, col_bits: 14, pad: 512, code_bits: 15, n_queries: 200 };

/// Placement of one weight tensor inside the flat commitment vector.
#[derive(Clone, Copy, Debug)]
pub struct TensorSlot {
    /// Logical rows (GEMM inner dim for the row-major tensor).
    pub k: usize,
    /// Logical columns.
    pub n: usize,
    pub k_pad: usize,
    pub n_pad: usize,
    /// Start of the block in the flat vector (multiple of `block_len`).
    pub offset: usize,
    /// `k_pad * n_pad`, a power of two.
    pub block_len: usize,
}

impl TensorSlot {
    /// Number of block-local variables = pad_bits(n) + pad_bits(k).
    pub fn point_len(&self) -> usize {
        self.block_len.trailing_zeros() as usize
    }
}

/// The four tensors of one layer, in order: c_attn, attn out-proj, ffn_up,
/// ffn_down. `total_len` is the commitment size (power of two, zero-padded
/// outside the blocks).
pub struct LayerWeightLayout {
    pub tensors: [TensorSlot; 4],
    pub total_len: usize,
}

impl LayerWeightLayout {
    /// Generic constructor from the four (k, n) shapes; places the padded
    /// blocks largest-first so every offset is a multiple of its block size.
    pub fn for_shapes(shapes: [(usize, usize); 4]) -> LayerWeightLayout {
        let mut tensors = shapes.map(|(k, n)| {
            let (k_pad, n_pad) = (k.next_power_of_two(), n.next_power_of_two());
            TensorSlot { k, n, k_pad, n_pad, offset: 0, block_len: k_pad * n_pad }
        });
        // Stable largest-first placement.
        let mut order: Vec<usize> = (0..4).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(tensors[i].block_len));
        let mut cursor = 0usize;
        for &i in &order {
            tensors[i].offset = cursor;
            cursor += tensors[i].block_len;
        }
        let total_len = cursor.next_power_of_two();
        for t in &tensors {
            assert!(t.offset % t.block_len == 0, "block offset not aligned");
        }
        LayerWeightLayout { tensors, total_len }
    }

    /// Flatten the four row-major i16 tensors (given in layout order) into
    /// the zero-padded commitment coefficient vector of `total_len` entries.
    pub fn place(&self, tensors: [&[i16]; 4]) -> Vec<i16> {
        let mut w = vec![0i16; self.total_len];
        for (t, src) in self.tensors.iter().zip(tensors) {
            assert_eq!(src.len(), t.k * t.n, "tensor shape mismatch");
            for l in 0..t.k {
                w[t.offset + l * t.n_pad..t.offset + l * t.n_pad + t.n]
                    .copy_from_slice(&src[l * t.n..(l + 1) * t.n]);
            }
        }
        w
    }

    /// Map a `WeightClaimP`-style point (r_j ‖ r_l, length
    /// pad_bits(n) + pad_bits(k)) for tensor `tensor_idx` to the
    /// `BlockClaim` on this commitment: the block's internal variables are
    /// exactly the tensor's point variables.
    pub fn block_claim(&self, tensor_idx: usize, point: &[Fp2]) -> BlockClaim {
        let t = &self.tensors[tensor_idx];
        assert_eq!(point.len(), t.point_len(), "point must be r_j ‖ r_l for this tensor");
        BlockClaim { offset: t.offset, point: point.to_vec() }
    }
}

/// The one-layer GPT-2 small layout (2^24 coefficients, matches `P4_LAYER`):
///
/// | tensor    |   k  ×  n   | k_pad × n_pad | block | offset   |
/// |-----------|-------------|---------------|-------|----------|
/// | c_attn    |  768 × 4096 |  1024 × 4096  | 2^22  | 0        |
/// | attn_proj |  768 ×  768 |  1024 × 1024  | 2^20  | 3·2^22   |
/// | ffn_up    |  768 × 3072 |  1024 × 4096  | 2^22  | 2^22     |
/// | ffn_down  | 3072 ×  768 |  4096 × 1024  | 2^22  | 2^23     |
///
/// c_attn is committed on the PERMUTED padded column layout the fused-layer
/// proof claims against (`volta_proto::cattn_permuted`: col' = third·1024 +
/// head·64 + l, 768 rows × 4096 cols row-major) — same 2^22 block, the
/// third/head fields become plain bit positions of the claim point.
pub fn layout_gpt2_layer() -> LayerWeightLayout {
    let layout =
        LayerWeightLayout::for_shapes([(768, 4096), (768, 768), (768, 3072), (3072, 768)]);
    debug_assert_eq!(layout.total_len, 1 << 24);
    debug_assert_eq!(
        layout.tensors.map(|t| t.offset),
        [0, 3 << 22, 1 << 22, 1 << 23]
    );
    layout
}

/// P3.5-measured PCS cost model (see ledger): one multi-claim opening costs
/// a fixed 0.12 s plus 0.0023 s per claim. Returns
/// `(prefill_s, response_s)` where `prefill_s` is the opening cost at
/// `n_claims` claims and `response_s` at 2× that many.
///
/// P6 constraint (plan of record): decode weight-GEMM claims are **deferred**
/// and proved stacked in one opening at end-of-response — never per-token
/// openings — so claims/response ≈ 2 × claims/prefill (prefill claims plus
/// the deferred decode claims), amortizing the 0.12 s fixed cost once per
/// response.
pub fn pcs_cost_projection(n_claims: usize) -> (f64, f64) {
    const FIXED_S: f64 = 0.12;
    const PER_CLAIM_S: f64 = 0.0023;
    (
        FIXED_S + PER_CLAIM_S * n_claims as f64,
        FIXED_S + PER_CLAIM_S * (2 * n_claims) as f64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p4_layer_params_geometry() {
        P4_LAYER.validate();
        assert_eq!(P4_LAYER.n_vars(), 24);
        assert_eq!(P4_LAYER.rows(), 1 << 10);
        assert_eq!(P4_LAYER.cols(), 1 << 14);
        // Same rate / hiding / query count as GPT2_FULL.
        let g = crate::ligero::GPT2_FULL;
        assert_eq!(P4_LAYER.col_bits, g.col_bits);
        assert_eq!(P4_LAYER.pad, g.pad);
        assert_eq!(P4_LAYER.code_bits, g.code_bits);
        assert_eq!(P4_LAYER.n_queries, g.n_queries);
    }

    #[test]
    fn gpt2_layer_offsets_table() {
        let l = layout_gpt2_layer();
        assert_eq!(l.total_len, 1 << 24);
        let expect = [
            // (k, n, k_pad, n_pad, offset, block_len)
            (768, 4096, 1024, 4096, 0, 1 << 22),
            (768, 768, 1024, 1024, 3 << 22, 1 << 20),
            (768, 3072, 1024, 4096, 1 << 22, 1 << 22),
            (3072, 768, 4096, 1024, 1 << 23, 1 << 22),
        ];
        for (t, e) in l.tensors.iter().zip(expect) {
            assert_eq!((t.k, t.n, t.k_pad, t.n_pad, t.offset, t.block_len), e);
            // BlockClaim invariants used by claim_geom.
            assert!(t.offset % t.block_len == 0);
            assert!(t.block_len >= 1 << P4_LAYER.col_bits, "block smaller than a matrix row");
        }
        // Blocks are disjoint and inside the commitment.
        let mut iv: Vec<(usize, usize)> =
            l.tensors.iter().map(|t| (t.offset, t.offset + t.block_len)).collect();
        iv.sort();
        for w in iv.windows(2) {
            assert!(w[0].1 <= w[1].0);
        }
        assert!(iv.last().unwrap().1 <= l.total_len);
    }

    #[test]
    fn place_zero_pads_and_positions() {
        let l = LayerWeightLayout::for_shapes([(3, 5), (2, 2), (3, 6), (6, 3)]);
        let t0: Vec<i16> = (1..=15).collect(); // 3×5
        let t1: Vec<i16> = (100..=103).collect(); // 2×2
        let t2: Vec<i16> = (200..218).collect(); // 3×6
        let t3: Vec<i16> = (300..318).collect(); // 6×3
        let w = l.place([&t0, &t1, &t2, &t3]);
        assert_eq!(w.len(), l.total_len);
        for (ti, src) in [(0usize, &t0), (1, &t1), (2, &t2), (3, &t3)] {
            let t = &l.tensors[ti];
            let mut seen = 0i64;
            for l_ in 0..t.k_pad {
                for j in 0..t.n_pad {
                    let v = w[t.offset + l_ * t.n_pad + j];
                    if l_ < t.k && j < t.n {
                        assert_eq!(v, src[l_ * t.n + j]);
                        seen += 1;
                    } else {
                        assert_eq!(v, 0, "padding not zero at tensor {ti} ({l_},{j})");
                    }
                }
            }
            assert_eq!(seen as usize, t.k * t.n);
        }
    }

    #[test]
    fn cost_projection_model() {
        let (p, r) = pcs_cost_projection(100);
        assert!((p - 0.35).abs() < 1e-12);
        assert!((r - 0.58).abs() < 1e-12);
        let (p0, r0) = pcs_cost_projection(0);
        assert_eq!((p0, r0), (0.12, 0.12));
    }
}

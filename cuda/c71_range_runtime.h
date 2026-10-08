// Internal C ABI, one host thread per context. Handles never expose device
// pointers; no implicit backend. A failed create can return a stopped context:
// it must still be closed. Every other error poisons the context permanently.
#pragma once
#include "c71_range_native.cuh"
#include "c71_dense_i16.cuh"
#include "c71_byte_gather.cuh"
#include "c71_nonlinear.cuh"
#include "c71_pcs_hash.cuh"
#include "c71_pcs_weight.cuh"

struct C71RangeContext;
using C71RangeAccount = int (*)(int64_t);
enum C71RangeKind : uint32_t { C71_U8, C71_I16, C71_PAIR, C71_CHILDREN, C71_GRAM, C71_CUBIC, C71_I64, C71_BYTE_PENDING, C71_HISTOGRAM_PENDING,
    C71_PCS_BASE, C71_PCS_HASH_PENDING, C71_PCS_DIGEST, C71_PCS_FRONTIER_PENDING,
    C71_PCS_WEIGHT_TILES, C71_PCS_POWERS };
struct C71RangeStats {
    // ABI 4: actual live device reservations (released after fence), aligned
    // capacities and logical payload. create() sets a budget, not a slab.
    // NOT driver/context/shared/stack overhead or the whole-pipeline GPU peak.
    uint64_t arena_bytes, live_capacity_bytes, peak_capacity_bytes, logical_bytes;
    // Submitted copy/zero bytes and attempted launches/fences, not a bus meter.
    uint64_t allocations, releases, h2d_bytes, d2h_bytes, zeroed_bytes, launches, fences;
    uint64_t host_owner_bytes, stopped, cleanup_failed;
    // W is global immutable storage, OUTSIDE the one temporary arena.
    // Retained on failed free; peak sums actual W + arena reservations.
    uint64_t weights_bytes, weights_loaded_bytes, weights_sealed, peak_reserved_bytes;
    uint64_t d2d_bytes;
};
static_assert(sizeof(C71RangeStats)==152);

extern "C" {
uint32_t c71_range_runtime_abi();
int c71_range_create(int device,uint64_t arena_bytes,uint64_t reserve_bytes,C71RangeAccount account,C71RangeContext** out);
int c71_range_close(C71RangeContext* context,C71RangeStats* final_stats);
const char* c71_range_error(const C71RangeContext* context);
int c71_range_stats(const C71RangeContext* context,C71RangeStats* stats);
int c71_range_abort(C71RangeContext*);
int c71_range_alloc(C71RangeContext*,uint32_t kind,uint64_t count,uint64_t* handle);
int c71_range_release(C71RangeContext*,uint64_t handle);
int c71_range_upload(C71RangeContext*,uint64_t handle,const void* input,uint64_t bytes);
int c71_range_zero(C71RangeContext*,uint64_t handle);
int c71_range_roots(C71RangeContext*,uint64_t input,uint32_t bottom,Fp3 alpha,uint64_t output,uint64_t first);
int c71_range_runtime_canopy(C71RangeContext*,uint64_t input,uint64_t output);
int c71_range_as_children(C71RangeContext*,uint64_t handle);
int c71_range_groups(C71RangeContext*,uint64_t input,const c71_range::Group*,uint64_t output);
int c71_range_runtime_h_sum(C71RangeContext*,uint64_t input,uint64_t output,uint32_t buckets);
int c71_range_runtime_h_fold(C71RangeContext*,uint64_t input,uint64_t output,Fp3 challenge);
int c71_range_runtime_child_fold(C71RangeContext*,uint64_t input,Fp3 challenge);
int c71_range_runtime_coefficients(C71RangeContext*,uint64_t input,const c71_range::Round*,c71_range::Cubic* output);
int c71_range_runtime_h_coefficients(C71RangeContext*,uint64_t input,const c71_range::Round*,c71_range::Cubic* output);
// Only a completed scalar root/terminal, never a whole-array host spill.
int c71_range_read(C71RangeContext*,uint64_t input,uint64_t* limbs,uint32_t count);
// W is installed once through contiguous <=256 MiB host windows. No device
// pointer export, replacement, per-row upload, or full-output host spill.
int c71_dense_weights_begin(C71RangeContext*,uint64_t words);
int c71_dense_weights_upload(C71RangeContext*,uint64_t first,const int16_t*,uint64_t words);
int c71_dense_weights_seal(C71RangeContext*);
// Public token IDs select original W rows; no host W read or new kernel.
int c71_dense_embedding(C71RangeContext*,uint64_t weight_offset,uint32_t vocabulary,uint32_t columns,
                        const uint32_t* tokens,uint32_t rows,uint64_t output);
int c71_dense_product(C71RangeContext*,uint64_t input,uint64_t weight_offset,c71_dense::Shape,uint64_t output);
// Borrow complete input rows in place; the parent handle retains capacity.
int c71_dense_product_rows(C71RangeContext*,uint64_t input,uint64_t first_row,uint64_t weight_offset,c71_dense::Shape,uint64_t output);
int c71_dense_quantize(C71RangeContext*,uint64_t raw,int32_t shift,uint64_t output);
// Zero affine terms have handle/offset zero and never read an input.
int c71_dense_pointwise(C71RangeContext*,uint64_t x,uint64_t x_first,uint64_t y,uint64_t y_first,
                        c71_dense::Pointwise,uint64_t output);
int c71_histogram_begin(C71RangeContext*,uint64_t histogram);
int c71_histogram_seal(C71RangeContext*,uint64_t histogram);
int c71_histogram_padding(C71RangeContext*,uint64_t histogram,uint64_t count);
int c71_signed_append_at(C71RangeContext*,uint64_t input,uint64_t first,uint64_t count,uint64_t output,uint64_t output_first);
int c71_original_read(C71RangeContext*,uint64_t input,uint32_t kind,uint64_t first,uint64_t count,void* output);
int c71_dense_rms(C71RangeContext*,uint64_t input,uint64_t first,uint64_t weight_offset,c71_nonlinear::Rms,
                  uint64_t product,uint64_t statistic,uint64_t output);
int c71_dense_qk(C71RangeContext*,uint64_t query,uint64_t first,uint64_t keys,c71_nonlinear::Attention,uint64_t output);
int c71_dense_pv(C71RangeContext*,const uint64_t* probabilities,const uint64_t* first,uint64_t values,c71_nonlinear::Attention,uint64_t output);
int c71_dense_softmax(C71RangeContext*,uint64_t input,uint64_t first,uint64_t table,uint64_t table_byte_offset,
                      uint64_t histogram,c71_nonlinear::Attention,const uint64_t* outputs);
int c71_dense_lookup(C71RangeContext*,uint64_t input,uint64_t first,uint64_t table,uint64_t table_byte_offset,
                     uint64_t histogram,uint64_t output);
int c71_dense_rope(C71RangeContext*,uint64_t input,uint64_t first,uint64_t table,uint64_t table_byte_offset,
                   c71_nonlinear::Rope,uint64_t output);
// Only public selected token IDs leave the owner; slack remains resident.
int c71_dense_argmax(C71RangeContext*,uint64_t input,uint64_t first,uint32_t rows,uint32_t columns,
                     uint64_t output,uint32_t* public_tokens);
// Pending windows cannot be read by range. The Rust layout owner verifies
// unique/complete source-row coverage before seal; C enforces memory safety,
// codec bounds and a sticky arithmetic flag, fenced once at publication.
int c71_byte_begin(C71RangeContext*,uint64_t output);
int c71_byte_scatter(C71RangeContext*,uint64_t input,const c71_byte::Tile*,uint64_t output);
int c71_byte_seal(C71RangeContext*,uint64_t output);
// Mandatory ABI-4 PCS extension. Canonical base words, digest bytes and
// incomplete chaining states are separate kinds; range cannot read them.
// Only salts/pads or reduced fixtures use upload; W/A producers stay resident.
int c71_pcs_words_upload(C71RangeContext*,uint64_t output,uint64_t first,const uint64_t*,uint64_t count);
// Eight column-major slots: pending four in slots 4..7, new four in 0..3.
// Start/finish use slots 0..3. Exactly 15 ordered steps, columns 4,12,..116.
int c71_pcs_leaf_start(C71RangeContext*,uint64_t ring,uint64_t states);
int c71_pcs_leaf_step(C71RangeContext*,uint64_t ring,uint64_t states,uint32_t first_column);
// Finish contiguous salt bands; publish only after all rows and sticky flag
// are complete. A small upload window avoids a second 1-GiB salt array.
int c71_pcs_leaf_finish(C71RangeContext*,uint64_t ring,uint64_t salts,uint64_t states,uint64_t first_row,uint64_t rows);
int c71_pcs_nodes(C71RangeContext*,uint64_t input,uint64_t output,uint64_t rows);
int c71_pcs_frontier_begin(C71RangeContext*,uint64_t frontier,uint64_t rows,uint32_t groups);
int c71_pcs_merge_group(C71RangeContext*,uint64_t frontier,uint64_t roots,uint32_t group);
int c71_pcs_tiles_upload(C71RangeContext*,uint64_t output,const c71_pcs::WeightTile*,uint64_t count);
int c71_pcs_powers(C71RangeContext*,uint64_t low,uint64_t high,c71_pcs::WeightShape);
int c71_pcs_twiddles(C71RangeContext*,uint64_t output,uint32_t log_rows);
int c71_pcs_ring_zero(C71RangeContext*,uint64_t output);
// Fused host submission: signed-wide original accumulation, private pads,
// then the existing finite FFT on four columns. Only arithmetic flag D2H.
int c71_pcs_weight(C71RangeContext*,uint64_t tiles,uint64_t pads,uint64_t low,uint64_t high,
    uint64_t twiddles,uint64_t ring,c71_pcs::WeightShape);
// Bounded digest publication only; no base values or intermediate CV spill.
int c71_pcs_read_digests(C71RangeContext*,uint64_t input,uint64_t first,uint64_t count,void* output);
}

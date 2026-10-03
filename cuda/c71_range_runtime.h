// Internal C ABI, one host thread per context. Handles never expose device
// pointers; no implicit backend. A failed create can return a stopped context:
// it must still be closed. Every other error poisons the context permanently.
#pragma once
#include "c71_range_native.cuh"
#include "c71_dense_i16.cuh"

struct C71RangeContext;
enum C71RangeKind : uint32_t { C71_U8, C71_I16, C71_PAIR, C71_CHILDREN, C71_GRAM, C71_CUBIC, C71_I64 };
struct C71RangeStats {
    // Requested arena reservation, assigned aligned capacities, logical payload.
    // NOT driver/context/shared/stack overhead or the whole-pipeline GPU peak.
    uint64_t arena_bytes, live_capacity_bytes, peak_capacity_bytes, logical_bytes;
    // Submitted copy/zero bytes and attempted launches/fences, not a bus meter.
    uint64_t allocations, releases, h2d_bytes, d2h_bytes, zeroed_bytes, launches, fences;
    uint64_t host_owner_bytes, stopped, cleanup_failed;
    // W is global immutable storage, OUTSIDE the one temporary arena.
    // Retained on failed free; peak sums actual W + arena reservations.
    uint64_t weights_bytes, weights_loaded_bytes, weights_sealed, peak_reserved_bytes;
};
static_assert(sizeof(C71RangeStats)==144);

extern "C" {
uint32_t c71_range_runtime_abi();
int c71_range_create(int device,uint64_t arena_bytes,uint64_t reserve_bytes,C71RangeContext** out);
int c71_range_close(C71RangeContext* context,C71RangeStats* final_stats);
const char* c71_range_error(const C71RangeContext* context);
int c71_range_stats(const C71RangeContext* context,C71RangeStats* stats);
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
int c71_dense_product(C71RangeContext*,uint64_t input,uint64_t weight_offset,c71_dense::Shape,uint64_t output);
int c71_dense_quantize(C71RangeContext*,uint64_t raw,int32_t shift,uint64_t output);
}

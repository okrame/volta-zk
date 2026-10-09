// Base PCS remainder queries on the existing numeric owner. No extension/MAC
// basis conversion and no source/challenge interface.
#pragma once
#include "c71_pcs_weight.cuh"
namespace c71_pcs {
struct QueryBlock {
    uint64_t first, source_rows, message_rows, active;
    uint64_t byte_first, window_first, pad_first, pad_rows;
    uint32_t pad_only;
};
static_assert(sizeof(QueryBlock)==72);
}

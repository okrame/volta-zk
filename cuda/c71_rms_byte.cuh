// Private original-byte fraction-tree evaluator. No transcript or MAC inputs.
#pragma once
#include "c71_rms_prefix.cuh"
#include <cuda_runtime_api.h>

namespace c71_rms_byte {
constexpr unsigned lanes=16, max_rank=17, max_features=lanes*max_rank;
constexpr unsigned max_bits=40, state_bytes=8u<<20, batch_pairs=4096;
constexpr unsigned factor_slots=(1u<<15)+(1u<<14), histogram_groups=128;
struct Shape {uint32_t bits,live_lanes,layer,features,round,checkpoint,stride,rows;};
struct FeatureRange {uint32_t first,count;};
static_assert(sizeof(Shape)==32 && sizeof(FeatureRange)==8);
// Metadata: query[40], emitted-prefix[40], lambda, baseline[16],
// lane-Eq[16], original public coefficient tables[16][256], then feature
// LUTs [feature][weight, values[256]]. Ranges are a separate byte tail.
// Weighted values are exactly weight*value, so only the unweighted state is
// retained; this changes no original polynomial, round or terminal.
constexpr unsigned prefix=max_bits, lambda=2*max_bits, baseline=lambda+1;
constexpr unsigned lane_eq=baseline+lanes, coefficients=lane_eq+lanes;
constexpr unsigned feature_lut=coefficients+lanes*256;
#ifdef __CUDACC__
cudaError_t factors(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t cell_baseline(cudaStream_t,Shape,const Fp3*,Fp3*);
cudaError_t regenerate(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,
    const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,const FeatureRange*,
    const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t fold_state(cudaStream_t,Shape,Fp3,Fp3*);
cudaError_t cell_coefficients(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,
    const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,const FeatureRange*,
    const Fp3*,const Fp3*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t sum_partials(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t histogram(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,
    const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t histogram_sum(cudaStream_t,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t histogram_padding(cudaStream_t,Shape,const Fp3*,unsigned,Fp3*);
cudaError_t recover(cudaStream_t,Shape,const Fp3*,const Fp3*,Fp3*);
cudaError_t fold_children(cudaStream_t,unsigned,Fp3,Fp3*);
cudaError_t child_coefficients(cudaStream_t,Shape,const Fp3*,const Fp3*,Fp3*);
#endif
}

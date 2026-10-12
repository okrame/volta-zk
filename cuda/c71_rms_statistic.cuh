// Original weighted P0 square reduction; private source, no MAC/FS inputs.
#pragma once
#include "c71_range_native.cuh"
#include <cuda_runtime_api.h>
namespace c71_rms_statistic {
constexpr unsigned max_bits=26,state_bytes=8u<<20,batch_pairs=4096;
constexpr unsigned factor_slots=2u<<13,prefix=max_bits;
struct Shape {uint32_t rows,columns,row_bits,column_bits,bits,checkpoint,round,stride,remaining;};
static_assert(sizeof(Shape)==36);
#ifdef __CUDACC__
cudaError_t factors(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t regenerate(cudaStream_t,Shape,const uint8_t*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t fold_state(cudaStream_t,unsigned,Fp3,Fp3*);
cudaError_t coefficients(cudaStream_t,Shape,const uint8_t*,const Fp3*,const Fp3*,const Fp3*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t reduce(cudaStream_t,const Fp3*,unsigned,Fp3*);
#endif
}

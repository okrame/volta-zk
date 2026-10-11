#pragma once
#include "c71_rms_prefix.cuh"
#include <cuda_runtime_api.h>
namespace c71_rms_index {
constexpr unsigned threads=256;
cudaError_t start(cudaStream_t,unsigned,unsigned,c71_rms_prefix::Gate*,const c71_rms_prefix::GateRange*,const Fp3*);
cudaError_t advance(cudaStream_t,unsigned,unsigned,unsigned,bool,const Fp3*,c71_rms_prefix::Gate*,Fp3*);
cudaError_t left(cudaStream_t,Fp3*,const Fp3*);
cudaError_t coefficients(cudaStream_t,unsigned,unsigned,unsigned,bool,bool,const c71_rms_prefix::Gate*,const Fp3*,Fp3*);
cudaError_t reduce(cudaStream_t,unsigned,bool,const Fp3*,Fp3*);
}

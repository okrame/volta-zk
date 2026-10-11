#pragma once
#include "c71_rms_prefix.cuh"
namespace c71_rms_tail {
using c71_range::Fp3;
constexpr unsigned max_half=4096,point_slots=58,factor_slots=4*max_half;
constexpr unsigned wire_lut=point_slots+factor_slots,selector_lut=wire_lut+512;
constexpr unsigned suffix=selector_lut+512,table_slots=suffix+512;
struct Shape {uint32_t width,programs,capacity,bits,round,n;};
cudaError_t prepare(cudaStream_t,Shape,Fp3*,unsigned*);
cudaError_t suffix_weights(cudaStream_t,Shape,unsigned,Fp3*);
cudaError_t fold(cudaStream_t,Shape,unsigned,unsigned,unsigned,const uint64_t*,const uint16_t*,const Fp3*,Fp3*);
cudaError_t gates(cudaStream_t,Shape,unsigned,const c71_rms_prefix::Gate*,unsigned,const Fp3*,Fp3*);
cudaError_t sum_gates(cudaStream_t,unsigned,unsigned,const Fp3*,Fp3*);
cudaError_t selector(cudaStream_t,Shape,unsigned,const Fp3*,const Fp3*,const Fp3*,Fp3*);
cudaError_t terminal_selectors(cudaStream_t,Shape,const Fp3*,Fp3*);
}

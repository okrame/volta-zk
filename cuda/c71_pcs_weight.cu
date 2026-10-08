// Original W scan and finite FFT on the existing owner's explicit stream.
#include <cuda_runtime.h>
#include <algorithm>
#include <cmath>
#include <vector>
#include "c71_pcs_weight.cuh"
#include "c71_fft.cuh"
namespace {
__global__ void fill_twiddles(uint64_t* output,uint64_t rows,uint64_t root) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<rows) output[i]=c71_pcs::power(root,i);
}
__global__ void powers(uint64_t* low,uint64_t* high,c71_pcs::WeightShape s,uint64_t omega) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<32*s.rows) {
        const unsigned lane=unsigned(i/s.rows);
        low[i]=c71_pcs::power(omega,uint64_t(s.first_coset+lane)*(i%s.rows));
    }
    if(i<32*c71_pcs::high_rows(s)) {
        const unsigned lane=unsigned(i%32);
        high[i]=c71_pcs::power(omega,uint64_t(s.first_coset+lane)*(i/32)*s.rows);
    }
}
__global__ void accumulate(const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,
    const uint64_t* high,uint64_t* ring,c71_pcs::WeightShape s,uint32_t* failed) {
    const uint64_t thread=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    const uint64_t task=thread/32;
    if(task>=4*s.rows) return; // every active warp has all 32 lanes
    const unsigned lane=thread%32, column=s.first_column+unsigned(task/s.rows);
    const uint64_t row=task%s.rows;
    c71_pcs::SignedWide sum{};
    for(uint64_t q=0;q<s.message_rows/s.rows;++q) {
        const uint64_t index=uint64_t(column)*s.message_rows+q*s.rows+row;
        if(index>=live) break; // public zero suffix, uniform across this warp
        int value=0;
        if(!lane) {
            const uint64_t address=c71_pcs::packed_address(tiles,tile_count,index,live);
            value=weights[address];
            if(value==INT16_MIN) atomicExch(failed,1);
        }
        value=__shfl_sync(0xffffffff,value,0);
        sum.add(int16_t(value),high[q*32+lane]);
    }
    uint64_t result=sum.residue();
    for(uint64_t j=row;j<s.pad_rows;j+=s.rows) {
        const uint64_t value=pads[uint64_t(column)*s.pad_rows+j];
        if(value>=P) { atomicExch(failed,1); return; }
        result=fp_add(result,fp_mul(value,high[((s.message_rows+j)/s.rows)*32+lane]));
    }
    ring[(s.slots+task/s.rows)*32*s.rows+uint64_t(lane)*s.rows+row]=
        fp_mul(result,low[uint64_t(lane)*s.rows+row]);
}
}
extern "C" cudaError_t c71_pcs_powers_launch(cudaStream_t stream,uint64_t* low,
    uint64_t* high,c71_pcs::WeightShape shape) {
    if(!stream || !low || !high || low==high || !c71_pcs::valid(shape)) return cudaErrorInvalidValue;
    const uint64_t height=shape.rows*shape.cosets;
    const uint64_t omega=c71_pcs::power(7,(P-1)/height);
    const uint64_t count=std::max(32*shape.rows,32*c71_pcs::high_rows(shape));
    powers<<<unsigned((count+255)/256),256,0,stream>>>(low,high,shape,omega);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_weight_launch(cudaStream_t stream,const int16_t* weights,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t live,const uint64_t* pads,
    const uint64_t* low,const uint64_t* high,uint64_t* ring,c71_pcs::WeightShape shape,uint32_t* failed) {
    if(!stream || !weights || !tiles || !tile_count || !pads || !low || !high || !ring || !failed ||
        !c71_pcs::valid(shape)) return cudaErrorInvalidValue;
    accumulate<<<unsigned((4*32*shape.rows+127)/128),128,0,stream>>>(
        weights,tiles,tile_count,live,pads,low,high,ring,shape,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_fft_launch(cudaStream_t stream,uint64_t* values,
    const uint64_t* twiddles,unsigned log_rows,unsigned batch,unsigned* attempted) {
    if(!stream || !values || !twiddles || log_rows<2 || log_rows>20 || log_rows%2 || !batch || batch>256)
        return cudaErrorInvalidValue;
    const unsigned log_side=log_rows/2;
    return c71_fft::launch_five_pass(stream,values,twiddles,size_t{1}<<log_side,log_side,batch,1,false,attempted);
}
extern "C" cudaError_t c71_pcs_twiddles_launch(cudaStream_t stream,uint64_t* twiddles,unsigned log_rows) {
    // Dedicated base powers; no generic/private RNG or float FFT.
    if(!stream || !twiddles || log_rows<2 || log_rows>20 || log_rows%2) return cudaErrorInvalidValue;
    const uint64_t rows=uint64_t{1}<<log_rows;
    const uint64_t root=c71_pcs::power(7,(P-1)/rows);
    fill_twiddles<<<unsigned((rows+255)/256),256,0,stream>>>(twiddles,rows,root);
    return cudaGetLastError();
}

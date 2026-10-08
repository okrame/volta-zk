// No source download or second owner. Pending accumulators publish only after
// full source coverage, original pads, finite FFT and the terminal flag fence.
#include <cuda_runtime.h>
#include <algorithm>
#include "c71_pcs_source.cuh"
#include "c71_pcs_hash.cuh"
namespace {
__device__ void add_field(uint64_t* output,uint64_t value) {
    auto* target=reinterpret_cast<unsigned long long*>(output);
    auto old=atomicCAS(target,0ULL,0ULL);
    for(;;) {
        const auto before=old;
        old=atomicCAS(target,before,c71_range::fp_add(before,value));
        if(old==before) return;
    }
}
__global__ void powers(uint64_t* low,uint64_t* high,c71_pcs::SourceShape s,uint64_t omega) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<4*s.rows) low[i]=c71_pcs::power(omega,uint64_t(s.first_coset+i/s.rows)*(i%s.rows));
    if(i<4*c71_pcs::high_rows(s)) high[i]=c71_pcs::power(omega,uint64_t(s.first_coset+i%4)*(i/4)*s.rows);
}
__global__ void tile(const void* input,unsigned kind,c71_pcs::SourceTile t,
    const uint64_t* high,uint64_t* first,uint64_t* second,uint64_t* counts,
    c71_pcs::SourceShape s,uint32_t* failed) {
    __shared__ unsigned histogram[256];
    if(counts) for(unsigned j=threadIdx.x;j<256;j+=blockDim.x) histogram[j]=0;
    if(counts) __syncthreads();
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<t.rows*t.columns) {
        const auto address=t.input_first+(i/t.columns)*t.input_stride+i%t.columns;
        const int64_t word=kind==1 ? static_cast<const int16_t*>(input)[address] : static_cast<const int64_t*>(input)[address];
        for(unsigned j=0;j<t.width;++j) {
            uint8_t byte=0;
            if(!c71_byte::encode(word,t.signed_width,t.byte_first+j,byte)) { atomicExch(failed,1); continue; }
            const uint64_t index=t.original_first+i*t.width+j;
            const unsigned column=unsigned(index/s.message_rows);
            const uint64_t within=index%s.message_rows, row=within%s.rows, q=within/s.rows;
            uint64_t* output=(column<64?first:second)+uint64_t(column%64)*4*s.rows;
            for(unsigned lane=0;lane<4;++lane)
                add_field(output+uint64_t(lane)*s.rows+row,c71_range::fp_mul(byte,high[q*4+lane]));
            if(counts) atomicAdd(histogram+byte,1u);
        }
    }
    if(counts) {
        __syncthreads();
        for(unsigned j=threadIdx.x;j<256;j+=blockDim.x)
            if(histogram[j]) atomicAdd(reinterpret_cast<unsigned long long*>(counts+j),static_cast<unsigned long long>(histogram[j]));
    }
}
__global__ void pad(uint64_t* values,const uint64_t* pads,const uint64_t* low,const uint64_t* high,
    c71_pcs::SourceShape s,unsigned first_column,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=64*4*s.rows) return;
    const unsigned column=first_column+unsigned(i/(4*s.rows)), lane=unsigned((i/s.rows)%4);
    const uint64_t row=i%s.rows;
    for(uint64_t j=row;j<s.pad_rows;j+=s.rows)
        if(pads[uint64_t(column)*s.pad_rows+j]>=c71_range::P) { atomicExch(failed,1); return; }
    values[i]=c71_pcs::padded(values[i],pads,low,high,s,column,row,lane);
}
__global__ void leaves(const uint64_t* first,const uint64_t* second,const uint64_t* salts,
    c71_pcs::Hash32* output,uint64_t rows,uint64_t begin,uint64_t count,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count) return;
    const uint64_t row=begin+i;
    for(unsigned column=0;column<128;++column)
        if((column<64?first:second)[uint64_t(column%64)*rows+row]>=c71_pcs::MODULUS) { atomicExch(failed,1); return; }
    for(unsigned j=0;j<4;++j) if(salts[uint64_t(j)*count+i]>=c71_pcs::MODULUS) { atomicExch(failed,1); return; }
    auto cv=c71_pcs::leaf_start(first,rows,row);
    for(unsigned column=4;column<=116;column+=8) {
        const auto* pending=(column<64?first:second)+uint64_t(column%64)*rows;
        const auto* next=(column+4<64?first:second)+uint64_t((column+4)%64)*rows;
        cv=c71_pcs::leaf_step(cv,pending,next,rows,row,column);
    }
    output[row]=c71_pcs::leaf_finish(cv,second+60*rows,salts,rows,row,count,i);
}
}
extern "C" cudaError_t c71_pcs_source_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,c71_pcs::SourceShape s) {
    if(!stream || !low || !high || low==high || !c71_pcs::valid(s)) return cudaErrorInvalidValue;
    const uint64_t count=std::max(4*s.rows,4*c71_pcs::high_rows(s));
    const uint64_t omega=c71_pcs::power(7,(c71_range::P-1)/(s.rows*s.cosets));
    powers<<<unsigned((count+255)/256),256,0,stream>>>(low,high,s,omega);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_source_tile_launch(cudaStream_t stream,const void* input,unsigned kind,c71_pcs::SourceTile t,
    const uint64_t* high,uint64_t* first,uint64_t* second,uint64_t* counts,c71_pcs::SourceShape s,uint32_t* failed) {
    if(!stream || !input || !high || !first || !second || first==second || !failed || !c71_pcs::valid(s)) return cudaErrorInvalidValue;
    tile<<<unsigned((t.rows*t.columns+127)/128),128,0,stream>>>(input,kind,t,high,first,second,counts,s,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_source_pad_launch(cudaStream_t stream,uint64_t* values,const uint64_t* pads,
    const uint64_t* low,const uint64_t* high,c71_pcs::SourceShape s,unsigned first_column,uint32_t* failed) {
    if(!stream || !values || !pads || !low || !high || !failed || !c71_pcs::valid(s) || (first_column!=0 && first_column!=64)) return cudaErrorInvalidValue;
    pad<<<unsigned((64*4*s.rows+255)/256),256,0,stream>>>(values,pads,low,high,s,first_column,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_full_leaves_launch(cudaStream_t stream,const uint64_t* first,const uint64_t* second,
    const uint64_t* salts,c71_pcs::Hash32* output,uint64_t rows,uint64_t begin,uint64_t count,uint32_t* failed) {
    if(!stream || !first || !second || first==second || !salts || !output || !failed || !rows || rows>(uint64_t{1}<<22) ||
        !count || begin>rows || count>rows-begin) return cudaErrorInvalidValue;
    leaves<<<unsigned((count+127)/128),128,0,stream>>>(first,second,salts,output,rows,begin,count,failed);
    return cudaGetLastError();
}

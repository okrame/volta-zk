#include <cuda_runtime.h>
#include "c71_dense_i16.cuh"
#include "c71_byte_gather.cuh"
using namespace c71_dense;

__device__ __forceinline__ void mma(int32_t (&d)[4],const uint32_t (&a)[4],const uint32_t (&b)[2]) {
    // No saturation or floating-point intermediate. Checked K bounds every
    // prefix of each accumulator, not merely the recomposed final result.
    asm volatile("mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
        : "+r"(d[0]),"+r"(d[1]),"+r"(d[2]),"+r"(d[3])
        : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
}
// 4 independent warps per CTA, output tile 16x32. Original X[M,K] and
// W[N,K] are row-major: W is already the MMA column-major right operand.
// ponytail: direct fragment loads, no extra W packing/cache; only add shared
// tiling after authorized profiling shows that repeated loads are material.
extern "C" __global__ void c71_dense_i16_mma(const int16_t* x,const int16_t* w,
    int64_t* out,uint32_t* failed,Shape s) {
    const unsigned lane=threadIdx.x%32, row0=blockIdx.y*16, col0=blockIdx.x*32+(threadIdx.x/32)*8;
    if(col0>=s.n) return; // Uniform within the entire warp, never a partial MMA.
    int32_t hh[4]{},hl[4]{},lh[4]{},ll[4]{},sx[2]{},sw=0;
    bool invalid=false;
    for(unsigned first=0;first<s.k;first+=32) {
        uint32_t ah[4]{},al[4]{},bh[2]{},bl[2]{};
#pragma unroll
        for(unsigned r=0;r<4;++r) {
#pragma unroll
            for(unsigned b=0;b<4;++b) {
                const unsigned row=row0+a_row(lane,r),k=first+a_k(lane,r,b);
                const int16_t v=row<s.m && k<s.k ? x[size_t(row)*s.k+k]:0;
                invalid|=v==INT16_MIN; sx[r%2]+=v; pack(v,b,ah[r],al[r]);
            }
        }
#pragma unroll
        for(unsigned r=0;r<2;++r) {
#pragma unroll
            for(unsigned b=0;b<4;++b) {
                const unsigned row=col0+w_row(lane),k=first+w_k(lane,r,b);
                const int16_t v=row<s.n && k<s.k ? w[size_t(row)*s.k+k]:0;
                invalid|=v==INT16_MIN; sw+=v; pack(v,b,bh[r],bl[r]);
            }
        }
        mma(hh,ah,bh); mma(hl,ah,bl); mma(lh,al,bh); mma(ll,al,bl);
    }
    const bool bad=__any_sync(0xffffffffu,invalid);
    if(bad && lane==0) atomicOr(failed,1u);
    // Four adjacent lanes partition K for each A row / W column. Integer
    // sums remain bounded by K*32768, safely below signed int32.
#pragma unroll
    for(unsigned shift=1;shift<=2;shift*=2) {
        sx[0]+=__shfl_xor_sync(0xffffffffu,sx[0],shift);
        sx[1]+=__shfl_xor_sync(0xffffffffu,sx[1],shift);
        sw+=__shfl_xor_sync(0xffffffffu,sw,shift);
    }
#pragma unroll
    for(unsigned r=0;r<4;++r) {
        const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
        const int32_t sum_w=__shfl_sync(0xffffffffu,sw,4*out_col(lane,r));
        const int64_t value=compose(hh[r],hl[r],lh[r],ll[r],sx[r/2],sum_w,(s.k+31)&~31u);
        if(row<s.m && col<s.n) out[size_t(row)*s.n+col]=value;
    }
}

// Internal pointer launcher, no allocator, reset, fence or CPU fallback. The
// resident caller must own capacities, initialize a sticky zero error flag,
// then fence/check it BEFORE using any result, including in another kernel.
extern "C" cudaError_t c71_dense_i16_launch(cudaStream_t stream,const int16_t* x,uint64_t x_words,
    const int16_t* w,uint64_t w_words,int64_t* out,uint64_t out_values,uint32_t* failed,Shape s) {
    if(!stream || !valid_buffers(x,x_words,w,w_words,out,out_values,failed,s)) return cudaErrorInvalidValue;
    c71_dense_i16_mma<<<dim3((s.n+31)/32,(s.m+15)/16),128,0,stream>>>(x,w,out,failed,s);
    return cudaGetLastError();
}

extern "C" __global__ void c71_dense_rne(const int64_t* raw,int16_t* output,uint64_t count,
                                        int32_t shift,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) {
        int16_t y=0;
        if(!quantize(raw[i],shift,y)) atomicOr(failed,1u);
        else output[i]=y;
    }
}
extern "C" cudaError_t c71_dense_rne_launch(cudaStream_t stream,const int64_t* raw,int16_t* output,
    uint64_t count,int32_t shift,uint32_t* failed) {
    uintptr_t re,oe,fe;
    if(!stream || !count || count>uint64_t(max_m)*max_n ||
       reinterpret_cast<uintptr_t>(raw)%8 || reinterpret_cast<uintptr_t>(output)%2 ||
       reinterpret_cast<uintptr_t>(failed)%4 || !span(raw,count*8,re) ||
       !span(output,count*2,oe) || !span(failed,4,fe) || overlaps(raw,re,output,oe) ||
       overlaps(raw,re,failed,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    c71_dense_rne<<<(count+255)/256,256,0,stream>>>(raw,output,count,shift,failed);
    return cudaGetLastError();
}

extern "C" __global__ void c71_dense_pointwise_kernel(const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,Pointwise op,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) {
        const int16_t a=(op.multiply || op.a)?x[i]:0, b=(op.multiply || op.b)?y[i]:0;
        int64_t value=0;
        if(!pointwise(a,b,op,value)) atomicOr(failed,1u);
        else output[i]=value;
    }
}
extern "C" cudaError_t c71_dense_pointwise_launch(cudaStream_t stream,const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,Pointwise op,uint32_t* failed) {
    uintptr_t oe,fe;
    if(!stream || !valid_pointwise(op) || !count || count>uint64_t(max_m)*max_n ||
       reinterpret_cast<uintptr_t>(output)%8 || reinterpret_cast<uintptr_t>(failed)%4 ||
       !span(output,count*8,oe) || !span(failed,4,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    const int16_t* inputs[]={x,y}; const bool used[]={op.multiply || op.a,op.multiply || op.b};
    for(unsigned j=0;j<2;++j) {
        uintptr_t end;
        if(used[j] ? (reinterpret_cast<uintptr_t>(inputs[j])%2 || !span(inputs[j],count*2,end) ||
           overlaps(inputs[j],end,output,oe) || overlaps(inputs[j],end,failed,fe)) : inputs[j]!=nullptr) return cudaErrorInvalidValue;
    }
    c71_dense_pointwise_kernel<<<(count+255)/256,256,0,stream>>>(x,y,output,count,op,failed);
    return cudaGetLastError();
}

extern "C" __global__ void c71_byte_scatter_kernel(const void* input,unsigned kind,
    uint8_t* output,uint32_t* failed,c71_byte::Tile t) {
    const uint64_t count=t.rows*t.columns*t.width;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t address=c71_byte::ordered(t.original_first+i,t);
        if(address<t.window_first || address-t.window_first>=t.window_length) continue;
        const uint64_t word=i/t.width, index=t.input_first+(word/t.columns)*t.input_stride+word%t.columns;
        const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
        uint8_t byte=0;
        if(!c71_byte::encode(value,t.signed_width,t.byte_first+i%t.width,byte)) atomicOr(failed,1u);
        else output[address-t.window_first]=byte;
    }
}
extern "C" cudaError_t c71_byte_scatter_launch(cudaStream_t stream,const void* input,unsigned kind,
    uint64_t input_count,uint8_t* output,uint64_t output_count,uint32_t* failed,c71_byte::Tile t) {
    uintptr_t ie,oe,fe;
    if(!stream || !c71_byte::valid(t,kind,input_count,output_count) ||
       reinterpret_cast<uintptr_t>(input)%(kind==1?2:8) || reinterpret_cast<uintptr_t>(failed)%4 ||
       input_count>UINT64_MAX/(kind==1?2:8) ||
       !span(input,input_count*(kind==1?2:8),ie) || !span(output,output_count,oe) || !span(failed,4,fe) ||
       overlaps(input,ie,output,oe) || overlaps(input,ie,failed,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    const uint64_t blocks=(t.rows*t.columns*t.width+255)/256;
    c71_byte_scatter_kernel<<<blocks>65535?65535:blocks,256,0,stream>>>(input,kind,output,failed,t);
    return cudaGetLastError();
}

// Candidate only: original scalar launchers remain unchanged. No staging,
// allocation, stream, coins, rounding, fence, or implicit backend is added.
#include <cuda_runtime.h>
#include "c71_attention_mma.cuh"
namespace {
using namespace c71_dense;
using namespace c71_attention;
__device__ __forceinline__ void mma(int32_t (&d)[4],const uint32_t (&a)[4],const uint32_t (&b)[2]) {
    asm volatile("mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
        : "+r"(d[0]),"+r"(d[1]),"+r"(d[2]),"+r"(d[3])
        : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
}
template<bool PV>
__device__ void tile(const int16_t* a,const int16_t* b,int64_t* output,uint32_t* failed,
    c71_nonlinear::Attention s,unsigned head) {
    const unsigned lane=threadIdx.x%32,row0=blockIdx.y*16,col0=blockIdx.x*32+(threadIdx.x/32)*8;
    const unsigned columns=PV ? s.lanes : s.old+150;
    if(col0>=columns) return; // Uniform warp: no partial MMA.
    if(!PV && col0>=tile_live(s,row0)) {
        for(unsigned r=0;r<4;++r) {
            const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
            if(output_live(s,PV,row,col)) output[output_index(s,PV,head,row,col)]=0;
        }
        return;
    }
    const unsigned bound=PV ? padded(tile_live(s,row0)) : padded(s.lanes);
    int32_t hh[4]{},hl[4]{},lh[4]{},ll[4]{},sx[2]{},sw=0;
    bool invalid=false;
    for(unsigned first=0;first<bound;first+=32) {
        uint32_t ah[4]{},al[4]{},bh[2]{},bl[2]{};
#pragma unroll
        for(unsigned r=0;r<4;++r) {
#pragma unroll
            for(unsigned byte=0;byte<4;++byte) {
                const unsigned row=row0+a_row(lane,r),k=first+a_k(lane,r,byte);
                const uint64_t index=PV ? pv_a_index(s,row,k) : qk_a_index(s,row,k);
                const int16_t value=load(a,index,invalid,PV);
                sx[r%2]+=value; pack(value,byte,ah[r],al[r]);
            }
        }
#pragma unroll
        for(unsigned r=0;r<2;++r) {
#pragma unroll
            for(unsigned byte=0;byte<4;++byte) {
                const unsigned col=col0+w_row(lane),k=first+w_k(lane,r,byte);
                const uint64_t index=PV ? pv_b_index(s,head,row0,col,k) : qk_b_index(s,row0,col,k);
                const int16_t value=load(b,index,invalid);
                sw+=value; pack(value,byte,bh[r],bl[r]);
            }
        }
        mma(hh,ah,bh); mma(hl,ah,bl); mma(lh,al,bh); mma(ll,al,bl);
    }
    if(__any_sync(0xffffffffu,invalid) && lane==0) atomicOr(failed,1u);
#pragma unroll
    for(unsigned shift=1;shift<=2;shift*=2) {
        sx[0]+=__shfl_xor_sync(0xffffffffu,sx[0],shift);
        sx[1]+=__shfl_xor_sync(0xffffffffu,sx[1],shift);
        sw+=__shfl_xor_sync(0xffffffffu,sw,shift);
    }
#pragma unroll
    for(unsigned r=0;r<4;++r) {
        const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
        const int32_t sum_b=__shfl_sync(0xffffffffu,sw,4*out_col(lane,r));
        const int64_t raw=compose(hh[r],hl[r],lh[r],ll[r],sx[r/2],sum_b,bound);
        if(output_live(s,PV,row,col))
            output[output_index(s,PV,head,row,col)]=output_value(s,PV,row,col,raw);
    }
}
__global__ void qk(const int16_t* query,const int16_t* keys,int64_t* output,
    c71_nonlinear::Attention s,uint32_t* failed) {
    tile<false>(query,keys,output,failed,s,s.head);
}
__global__ void pv(PiPointers probabilities,const int16_t* values,int64_t* output,
    c71_nonlinear::Attention s,uint32_t* failed) {
    const unsigned head=blockIdx.z;
    tile<true>(probabilities.heads[head],values,output,failed,s,head);
}
}
extern "C" cudaError_t c71_qk_mma_launch(cudaStream_t stream,const int16_t* query,const int16_t* keys,
    int64_t* output,c71_nonlinear::Attention s,uint32_t* failed) {
    if(!stream || !query || !keys || !output || !failed || !c71_nonlinear::valid(s)) return cudaErrorInvalidValue;
    qk<<<dim3((s.old+150+31)/32,(s.rows+15)/16),128,0,stream>>>(query,keys,output,s,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pv_mma_launch(cudaStream_t stream,const int16_t* const* probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention s,uint32_t* failed) {
    if(!stream || !probabilities || !values || !output || !failed || !c71_nonlinear::valid(s)) return cudaErrorInvalidValue;
    c71_attention::PiPointers pointers{};
    for(unsigned head=0;head<32;++head) {
        if(!probabilities[head]) return cudaErrorInvalidValue;
        pointers.heads[head]=probabilities[head];
    }
    pv<<<dim3((s.lanes+31)/32,(s.rows+15)/16,32),128,0,stream>>>(pointers,values,output,s,failed);
    return cudaGetLastError();
}

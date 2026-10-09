// Exact accumulation selected by the runner. No allocation, owner reset,
// host fence, field download, CPU fallback, RNG, transcript or MAC.
#include <cuda_runtime.h>
#include "c71_pcs_weight_tensor.cuh"

namespace {
__device__ __forceinline__ void mma(int32_t (&d)[4],const uint32_t (&a)[4],const uint32_t (&b)[2]) {
    // Identical dense INT8 instruction/fragment layout to c71_dense_i16.cu.
    // https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#warp-level-matrix-fragment-mma-16832
    asm volatile("mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
        : "+r"(d[0]),"+r"(d[1]),"+r"(d[2]),"+r"(d[3])
        : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
}

__global__ void accumulate(const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,
    const uint64_t* high,uint64_t* ring,c71_pcs::WeightShape s,uint32_t* failed) {
    using namespace c71_dense;
    using namespace c71_pcs_tensor;
    // CTA M = four original rows in each of four columns; CTA N = 32 coset.
    // Each warp computes eight coset. ALL limbs/warps share this one original
    // W load: each live (column,row,q) is read exactly once per launch.
    __shared__ int16_t original[mma_rows][shared_stride];
    const unsigned lane=threadIdx.x%32, warp=threadIdx.x/32;
    const uint64_t row0=uint64_t(blockIdx.x)*rows_per_column;
    const unsigned q_count=needed_q(s,live,row0), padded_q=(q_count+31)&~31u;
    for(unsigned i=threadIdx.x;i<mma_rows*padded_q;i+=threads) {
        const unsigned a=i/padded_q, q=i%padded_q;
        const unsigned column=s.first_column+a/rows_per_column;
        const uint64_t row=row0+a%rows_per_column;
        const uint64_t index=uint64_t(column)*s.message_rows+uint64_t(q)*s.rows+row;
        int16_t value=0;
        if(q<q_count && index<live) {
            value=weights[c71_pcs::packed_address(tiles,tile_count,index,live)];
            if(value==INT16_MIN) { atomicOr(failed,1u); value=0; }
        }
        original[a][q]=value;
    }
    __syncthreads(); // every one of the 128 threads reaches this, also q=0

    c71_pcs::SignedWide sums[4]{};
    bool invalid=false;
    // ponytail: retain only W in shared (8448 B). Four limb passes reread the
    // small high table instead of a 64 KiB shared copy or five dot arrays.
    // Profile factor-cache traffic and register spills before adding staging.
    for(unsigned limb=0;limb<limbs;++limb) {
        int32_t hh[4]{},hl[4]{},lh[4]{},ll[4]{},sx[2]{},sw=0;
        for(unsigned first=0;first<padded_q;first+=32) {
            uint32_t ah[4]{},al[4]{},bh[2]{},bl[2]{};
#pragma unroll
            for(unsigned r=0;r<4;++r) {
#pragma unroll
                for(unsigned b=0;b<4;++b) {
                    const int16_t value=original[a_row(lane,r)][first+a_k(lane,r,b)];
                    sx[r%2]+=value; pack(value,b,ah[r],al[r]);
                }
            }
#pragma unroll
            for(unsigned r=0;r<2;++r) {
#pragma unroll
                for(unsigned b=0;b<4;++b) {
                    const unsigned q=first+w_k(lane,r,b), coset=warp*8+w_row(lane);
                    const uint64_t factor=q<q_count?high[uint64_t(q)*32+coset]:0;
                    invalid|=factor>=P;
                    // A padded K operand is ZERO signed data, not digit(0),
                    // so dense compose's padded-K correction still applies.
                    const int16_t value=q<q_count?digit(factor,limb):0;
                    sw+=value; pack(value,b,bh[r],bl[r]);
                }
            }
            mma(hh,ah,bh); mma(hl,ah,bl); mma(lh,al,bh); mma(ll,al,bl);
        }
#pragma unroll
        for(unsigned shift=1;shift<=2;shift*=2) {
            sx[0]+=__shfl_xor_sync(0xffffffffu,sx[0],shift);
            sx[1]+=__shfl_xor_sync(0xffffffffu,sx[1],shift);
            sw+=__shfl_xor_sync(0xffffffffu,sw,shift);
        }
#pragma unroll
        for(unsigned r=0;r<4;++r) {
            const int32_t sum_digit=__shfl_sync(0xffffffffu,sw,4*out_col(lane,r));
            const int64_t dot=compose(hh[r],hl[r],lh[r],ll[r],sx[r/2],sum_digit,padded_q);
            invalid|=!add_dot(sums[r],dot,sx[r/2],limb);
        }
    }
    if(__any_sync(0xffffffffu,invalid)) {
        if(!lane) atomicOr(failed,1u);
        return; // uniform warp exit; no later CTA synchronization
    }
#pragma unroll
    for(unsigned r=0;r<4;++r) {
        const unsigned a=out_row(lane,r), column=s.first_column+a/rows_per_column;
        const uint64_t row=row0+a%rows_per_column;
        const unsigned coset=warp*8+out_col(lane,r);
        uint64_t value=sums[r].residue();
        bool bad=false;
        for(uint64_t j=row;j<s.pad_rows;j+=s.rows) {
            const uint64_t pad=pads[uint64_t(column)*s.pad_rows+j];
            if(pad>=P) { bad=true; break; }
            value=fp_add(value,fp_mul(pad,high[((s.message_rows+j)/s.rows)*32+coset]));
        }
        const uint64_t factor=low[uint64_t(coset)*s.rows+row];
        if(bad || factor>=P) atomicOr(failed,1u);
        else ring[(s.slots+a/rows_per_column)*32*s.rows+uint64_t(coset)*s.rows+row]=
            fp_mul(value,factor);
    }
}
}

// SAME pointer/shape contract as c71_pcs_weight_launch. The owner uses borrowed
// handles/stream and its sticky flag, validates capacities/public tiles and
// fences/checks BEFORE publishing to hash.
// The owner's existing finite FFT and terminal flag guard remain shared. This
// launcher alone is not a new owner and does not certify pointer provenance.
extern "C" cudaError_t c71_pcs_weight_tensor_launch(cudaStream_t stream,const int16_t* weights,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t live,const uint64_t* pads,
    const uint64_t* low,const uint64_t* high,uint64_t* ring,c71_pcs::WeightShape shape,uint32_t* failed) {
    if(!stream || !weights || !tiles || !tile_count || !pads || !low || !high || !ring || !failed ||
       !c71_pcs::valid(shape) || live>128*shape.message_rows) return cudaErrorInvalidValue;
    accumulate<<<unsigned(shape.rows/c71_pcs_tensor::rows_per_column),c71_pcs_tensor::threads,0,stream>>>(
        weights,tiles,tile_count,live,pads,low,high,ring,shape,failed);
    return cudaGetLastError();
}

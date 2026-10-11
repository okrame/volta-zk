#include <cuda_runtime.h>
#include "c71_rms_prefix.cuh"

namespace c71_rms_prefix {
namespace {
__device__ unsigned eq_at(unsigned tile,unsigned word,unsigned bit) {
    return (tile*8+word)*192+bit;
}
__device__ uint64_t reduce(uint64_t lo,uint32_t hi) {
    uint64_t value=lo+uint64_t(hi)*EPSILON;
    if(value<lo) value+=EPSILON;
    return value>=P?value-P:value;
}
__device__ void shift_count(uint64_t& lo,uint32_t& hi,unsigned count,unsigned bit) {
    const uint64_t term=uint64_t(count)<<bit, next=lo+term;
    hi+=uint32_t(bit?uint64_t(count)>>(64-bit):0)+uint32_t(next<lo);
    lo=next;
}
__global__ void original_replay(const uint8_t* frames,const uint16_t* assignments,
    const Program* programs,const Node* nodes,const uint32_t* boundaries,
    const uint32_t* outputs,unsigned program_count,unsigned width,unsigned capacity,
    unsigned n,uint64_t* stage) {
    if(blockIdx.x*4>=n) return;
    extern __shared__ uint64_t values[];
    __shared__ uint64_t live_words[2];
    for(unsigned wire=threadIdx.x;wire<width;wire+=blockDim.x)
        stage[size_t(wire)*(capacity/4)+blockIdx.x]=0;
    for(unsigned p=0;p<program_count;++p) {
        const Program plan=programs[p];
        if(threadIdx.x<64) {
            const unsigned local=blockIdx.x*4+threadIdx.x/16, row=threadIdx.x%16;
            const unsigned lane=threadIdx.x&31, warp=threadIdx.x/32;
            const size_t index=size_t(row)*capacity+local;
            const bool live=local<n && assignments[index]==p;
            uint32_t* words=reinterpret_cast<uint32_t*>(values);
            const uint32_t alive=__ballot_sync(0xffffffffu,live);
            if(lane==0) { live_words[warp]=alive; words[warp]=0; words[2+warp]=alive; }
            for(unsigned bit=0;bit<plan.ports-2;++bit) {
                const unsigned value=live?((frames[index*12+bit/8]>>(bit%8))&1):0;
                const uint32_t bits=__ballot_sync(0xffffffffu,value);
                if(lane==0) words[2*(bit+2)+warp]=bits;
            }
        }
        __syncthreads();
        if(live_words[0] || live_words[1]) {
            for(unsigned s=0;s<plan.stages;++s) {
                for(unsigned i=boundaries[plan.boundaries_first+s]+threadIdx.x;
                    i<boundaries[plan.boundaries_first+s+1];i+=blockDim.x) {
                    const Node g=nodes[plan.nodes_first+i];
                    const uint64_t x=values[g.x],y=values[g.y];
                    values[g.z]=g.op?(x^y):(x&y);
                }
                __syncthreads(); // Retired slots are reusable after this barrier.
            }
            for(unsigned wire=threadIdx.x;wire<plan.outputs_count;wire+=blockDim.x)
                stage[size_t(wire)*(capacity/4)+blockIdx.x]|=values[outputs[plan.outputs_first+wire]];
        }
        __syncthreads(); // Publish all programs' original wire positions.
    }
}
__global__ void transpose(uint64_t* stage,unsigned width,unsigned capacity) {
    const unsigned tiles=capacity/256,wire=blockIdx.x/tiles,tile=blockIdx.x%tiles;
    if(wire>=width) return;
    uint64_t* input=stage+(size_t(wire)*tiles+tile)*64;
    __shared__ uint64_t snapshot[64];
    if(threadIdx.x<64) snapshot[threadIdx.x]=input[threadIdx.x];
    __syncthreads();
    const unsigned row=threadIdx.x%16,word=threadIdx.x/16;
    uint32_t value=0;
    for(unsigned q=0;q<8;++q) {
        const uint64_t bits=(snapshot[word*8+q]>>row)&0x0001000100010001ULL;
        value|=uint32_t((bits*0x0001000200040008ULL)>>48&15)<<(q*4);
    }
    reinterpret_cast<uint32_t*>(input)[row*8+word]=value; // Row15 is ORIGINAL.
}
__global__ void original_eq(const Fp3* point,unsigned bits,unsigned first,unsigned capacity,
    unsigned n,uint32_t* planes) {
    const unsigned k=blockIdx.x*blockDim.x+threadIdx.x,lane=threadIdx.x&31;
    if(k>=capacity) return; // capacity and launches are multiples of256.
    Fp3 weight{};
    if(k<n) weight=c71_range::equality(point,bits,size_t(first)+k);
    const uint64_t limbs[3]={weight.c0,weight.c1,weight.c2};
    for(unsigned limb=0;limb<3;++limb) for(unsigned bit=0;bit<64;++bit) {
        const uint32_t plane=__ballot_sync(0xffffffffu,(limbs[limb]>>bit)&1);
        if(lane==0) planes[eq_at(k/256,(k%256)/32,limb*64+bit)]=plane;
    }
}
// A warp owns one gate and eight output columns. Each bit's K-tile counts
// remain in registers and are immediately reconstructed into canonical limbs.
// No global u32 count planes, read/modify/write or count-zero launch.
__global__ void binary_moments(const uint32_t* stage,const uint32_t* eq,const Gate* gates,
    unsigned gate_count,unsigned tiles,Fp3* chunk) {
    const unsigned lane=threadIdx.x&31,job=(blockIdx.x*blockDim.x+threadIdx.x)/32;
    if(job>=gate_count*2) return;
    const unsigned gate=job/2,half=job&1;
    const Gate g=gates[gate];
    Fp3 result[4]{};
    if(g.op!=2) for(unsigned limb=0;limb<3;++limb) {
        uint64_t lo[4]{}; uint32_t hi[4]{};
        for(unsigned bit=0;bit<64;++bit) {
            int acc[4]{};
            for(unsigned tile=0;tile<tiles;++tile) {
                uint32_t a[4],b[2];
                for(unsigned r=0;r<4;++r) {
                    const unsigned row=lane/4+8*(r&1),word=lane%4+4*(r/2);
                    a[r]=stage[(size_t(g.x)*tiles+tile)*128+row*8+word];
                }
                for(unsigned r=0;r<2;++r) {
                    const unsigned word=lane%4+4*r,row=lane/4+half*8;
                    b[r]=stage[(size_t(g.y)*tiles+tile)*128+row*8+word]
                        &eq[eq_at(tile,word,limb*64+bit)];
                }
                asm volatile("mma.sync.aligned.m16n8k256.row.col.s32.b1.b1.s32.and.popc "
                    "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
                    : "+r"(acc[0]),"+r"(acc[1]),"+r"(acc[2]),"+r"(acc[3])
                    : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
            }
            for(unsigned r=0;r<4;++r) shift_count(lo[r],hi[r],unsigned(acc[r]),bit);
        }
        for(unsigned r=0;r<4;++r) {
            const uint64_t value=reduce(lo[r],hi[r]);
            if(limb==0) result[r].c0=value;
            else if(limb==1) result[r].c1=value;
            else result[r].c2=value;
        }
    }
    for(unsigned r=0;r<4;++r) {
        const unsigned row=lane/4+8*(r/2),col=half*8+2*(lane%4)+(r&1);
        chunk[size_t(gate)*moments+row*16+col]=result[r];
    }
}
// Copy and XOR margins have sixteen separate ORIGINAL rows, including15.
__global__ void linear_moments(const uint32_t* stage,const uint32_t* eq,const Gate* gates,
    unsigned gate_count,unsigned tiles,Fp3* chunk) {
    const unsigned job=blockIdx.x*blockDim.x+threadIdx.x;
    if(job>=gate_count*16) return;
    const unsigned gate=job/16,row=job%16;const Gate g=gates[gate];
    Fp3 result{};
    if(g.op!=0) for(unsigned limb=0;limb<3;++limb) {
        uint64_t lo=0;uint32_t hi=0;
        for(unsigned bit=0;bit<64;++bit) {
            unsigned count=0;
            for(unsigned tile=0;tile<tiles;++tile) for(unsigned word=0;word<8;++word) {
                const uint32_t weight=eq[eq_at(tile,word,limb*64+bit)];
                count+=__popc(stage[(size_t(g.x)*tiles+tile)*128+row*8+word]&weight);
                if(g.op==1) count+=__popc(stage[(size_t(g.y)*tiles+tile)*128+row*8+word]&weight);
            }
            shift_count(lo,hi,count,bit);
        }
        const uint64_t value=reduce(lo,hi);
        if(limb==0) result.c0=value;else if(limb==1) result.c1=value;else result.c2=value;
    }
    chunk[size_t(gate)*moments+256+row]=result;
}
__global__ void late_weight(const Gate* gates,unsigned gate_count,const Fp3* chunk,Fp3* aggregate) {
    const unsigned slot=blockIdx.x*blockDim.x+threadIdx.x;
    if(slot>=moments) return;
    Fp3 sum=aggregate[slot];
    for(unsigned g=0;g<gate_count;++g) {
        if((slot<256 && gates[g].op==2) || (slot>=256 && gates[g].op==0)) continue;
        Fp3 term=mul6(chunk[size_t(g)*moments+slot],gates[g].weight);
        if(slot<256 && gates[g].op==1) term=sub(Fp3{},add(term,term));
        sum=add(sum,term);
    }
    aggregate[slot]=sum;
}
}
cudaError_t replay(cudaStream_t stream,const uint8_t* frames,const uint16_t* assignments,
    const Program* programs,const Node* nodes,const uint32_t* boundaries,const uint32_t* outputs,
    unsigned count,unsigned width,unsigned capacity,unsigned n,unsigned shared_slots,uint64_t* stage) {
    if(!n||n>capacity||capacity>4096||capacity%256||!count||count>421||!width||width>16384||shared_slots<2||shared_slots>16384)
        return cudaErrorInvalidValue;
    auto status=cudaMemsetAsync(stage,0,size_t(width)*capacity*2,stream);
    if(status!=cudaSuccess) return status;
    status=cudaFuncSetAttribute(original_replay,cudaFuncAttributeMaxDynamicSharedMemorySize,shared_slots*8);
    if(status!=cudaSuccess) return status;
    original_replay<<<(n+3)/4,128,shared_slots*8,stream>>>(frames,assignments,programs,nodes,boundaries,outputs,count,width,capacity,n,stage);
    status=cudaGetLastError();if(status!=cudaSuccess) return status;
    transpose<<<width*(capacity/256),128,0,stream>>>(stage,width,capacity);
    return cudaGetLastError();
}
cudaError_t suffix_eq(cudaStream_t stream,const Fp3* point,unsigned bits,unsigned first,
    unsigned capacity,unsigned n,uint32_t* planes) {
    if(!bits||bits>25||!n||n>capacity||capacity>4096||capacity%256||first>=(1u<<bits)||n>(1u<<bits)-first)
        return cudaErrorInvalidValue;
    original_eq<<<capacity/256,256,0,stream>>>(point,bits,first,capacity,n,planes);
    return cudaGetLastError();
}
cudaError_t consume(cudaStream_t stream,const uint32_t* stage,const uint32_t* eq,const Gate* gates,
    unsigned count,unsigned capacity,Fp3* chunk,Fp3* aggregate) {
    if(!count||count>gate_chunk||capacity>4096||capacity%256||!capacity) return cudaErrorInvalidValue;
    binary_moments<<<(count*64+127)/128,128,0,stream>>>(stage,eq,gates,count,capacity/256,chunk);
    auto status=cudaGetLastError();if(status!=cudaSuccess) return status;
    linear_moments<<<(count*16+127)/128,128,0,stream>>>(stage,eq,gates,count,capacity/256,chunk);
    status=cudaGetLastError();if(status!=cudaSuccess) return status;
    late_weight<<<3,128,0,stream>>>(gates,count,chunk,aggregate);
    return cudaGetLastError();
}
}

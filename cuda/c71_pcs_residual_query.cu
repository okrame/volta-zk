#include <cuda_runtime.h>
#include "c71_pcs_residual_query.cuh"

namespace {
namespace query=c71_pcs_residual_query;
namespace pcs=c71_pcs_residual;
__device__ void atomic_field(uint64_t* address,uint64_t value) {
    if(!value) return;
    auto* pointer=reinterpret_cast<unsigned long long*>(address);
    unsigned long long old=atomicCAS(pointer,0ULL,0ULL),seen;
    do { seen=old; old=atomicCAS(pointer,seen,fp_add(seen,value)); } while(old!=seen);
}
__global__ void initialize_weights(const pcs::E* pads,uint64_t* low,uint64_t capacity,
    c71_pcs::QueryBlock block,uint32_t* flag) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=capacity) return;
    const uint64_t j=block.first+i;
    pcs::E value{};
    if(j<block.source_rows && (block.pad_only || j>=block.message_rows) &&
       !query::pad_at(pads,block,j,value)) {atomicExch(flag,1u);value={};}
    low[i]=value.c0; low[capacity+i]=value.c1; low[2*capacity+i]=value.c2;
}
__global__ void weight_partials(const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,pcs::Shape shape,
    const pcs::Chunk* chunks,const pcs::E* tables,uint64_t* low,uint64_t capacity,
    c71_pcs::QueryBlock block,query::WeightWork work,uint32_t* flag) {
    __shared__ pcs::E equality[query::prefix_tile];
    __shared__ pcs::E partial[query::threads];
    const unsigned lane=threadIdx.x%query::coefficient_tile,worker=threadIdx.x/query::coefficient_tile;
    const uint64_t length=uint64_t{1}<<shape.remaining;
    for(uint64_t task=blockIdx.x;task<work.tasks;task+=gridDim.x) {
        const uint64_t coefficient_first=(task/work.prefix_tiles)*query::coefficient_tile;
        const uint64_t prefix_first=(task%work.prefix_tiles)*query::prefix_tile;
        const uint64_t cached_prefix=prefix_first+threadIdx.x;
        pcs::E factor{};
        if(cached_prefix<work.prefixes &&
           !query::checked_equality(cached_prefix,shape.equality,chunks,tables,factor)) {
            atomicExch(flag,1u); factor={};
        }
        equality[threadIdx.x]=factor;
        __syncthreads();
        const uint64_t coefficient=coefficient_first+lane;
        pcs::E sum{};
        if(coefficient<work.message_count) {
            const uint64_t local=block.byte_first+block.first+coefficient;
            for(unsigned p=worker;p<query::prefix_tile;p+=query::workers) {
                const uint64_t prefix=prefix_first+p;
                if(prefix>=work.prefixes) break;
                const uint64_t index=prefix*length+local;
                if(index>=shape.live) break; // BEFORE packed_address and W read
                const uint64_t address=c71_pcs::packed_address(tiles,tile_count,index,shape.live);
                uint64_t original=0;
                if(address>=input_words || !pcs::weight_scalar(input[address],original)) {
                    atomicExch(flag,1u); continue;
                }
                sum=pcs::add(sum,pcs::base_mul(equality[p],original));
            }
        }
        partial[threadIdx.x]=sum;
        __syncthreads();
        if(threadIdx.x<query::coefficient_tile && coefficient<work.message_count) {
            pcs::E combined=partial[threadIdx.x];
            for(unsigned w=1;w<query::workers;++w) combined=pcs::add(combined,partial[w*query::coefficient_tile+threadIdx.x]);
            atomic_field(low+coefficient,combined.c0);
            atomic_field(low+capacity+coefficient,combined.c1);
            atomic_field(low+2*capacity+coefficient,combined.c2);
        }
        __syncthreads(); // shared arrays may now be reused by the next task
    }
}
template<bool retained> __global__ void load(const int16_t* weights,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,pcs::ConstPlanes planes,
    pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,const pcs::E* pads,
    uint64_t* low,uint64_t capacity,c71_pcs::QueryBlock block,uint32_t* flag) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=capacity) return;
    pcs::E value{};
    bool ok;
    if constexpr(retained)
        ok=query::resident_at(planes,input_words,shape,chunks,tables,pads,block,block.first+i,value);
    else
        ok=query::weights_at(weights,input_words,tiles,tile_count,shape,chunks,tables,pads,block,block.first+i,value);
    if(!ok) { atomicExch(flag,1u); value={}; }
    low[i]=value.c0; low[capacity+i]=value.c1; low[2*capacity+i]=value.c2;
}
}
extern "C" cudaError_t c71_pcs_residual_query_weights_launch(cudaStream_t stream,
    const int16_t* input,uint64_t input_words,const c71_pcs::WeightTile* tiles,uint64_t tile_count,
    pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,const pcs::E* pads,uint64_t pad_count,
    uint64_t* low,uint64_t capacity,c71_pcs::QueryBlock block,uint32_t* flag,unsigned* attempted) {
    if(!stream || !input || !tiles || !tile_count || tile_count>65536 || !flag || !attempted ||
       *attempted>UINT32_MAX-2 || input_words<shape.live ||
       static_cast<const void*>(input)==static_cast<const void*>(low) ||
       !query::valid_arguments(shape,capacity,block,chunks,tables,pads,pad_count,low)) return cudaErrorInvalidValue;
    ++*attempted;
    initialize_weights<<<unsigned((capacity+query::threads-1)/query::threads),query::threads,0,stream>>>(pads,low,capacity,block,flag);
    if(const auto status=cudaGetLastError();status!=cudaSuccess) return status;
    const auto work=query::weight_work(shape,capacity,block);
    if(!work.tasks) return cudaSuccess;
    ++*attempted;
    const unsigned grid=unsigned(work.tasks<query::max_blocks ? work.tasks : query::max_blocks);
    weight_partials<<<grid,query::threads,0,stream>>>(input,input_words,tiles,tile_count,shape,chunks,tables,low,capacity,block,work,flag);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_query_resident_launch(cudaStream_t stream,
    pcs::ConstPlanes input,uint64_t input_count,pcs::Shape shape,const pcs::Chunk* chunks,
    const pcs::E* tables,const pcs::E* pads,uint64_t pad_count,uint64_t* low,uint64_t capacity,
    c71_pcs::QueryBlock block,uint32_t* flag) {
    if(!stream || !flag || !query::valid_shape(shape,true) || input_count!=shape.live ||
       !query::valid_arguments(shape,capacity,block,chunks,tables,pads,pad_count,low)) return cudaErrorInvalidValue;
    const uint64_t* sources[]={input.c0,input.c1,input.c2};
    for(unsigned i=0;i<3;++i) {
        if(!sources[i] || sources[i]==low) return cudaErrorInvalidValue;
        for(unsigned j=0;j<i;++j) if(sources[i]==sources[j]) return cudaErrorInvalidValue;
    }
    load<true><<<unsigned((capacity+query::threads-1)/query::threads),query::threads,0,stream>>>(
        nullptr,input_count,nullptr,0,input,shape,chunks,tables,pads,low,capacity,block,flag);
    return cudaGetLastError();
}

// One fused original scan per round on the numerical producer's common stream.
#include <cuda_runtime.h>
#include "c71_linear_native.cuh"

namespace {
__device__ void atomic_field(uint64_t* address,uint64_t value) {
    auto* pointer=reinterpret_cast<unsigned long long*>(address);
    unsigned long long old=atomicCAS(pointer,0,0),seen;
    do { seen=old; old=atomicCAS(pointer,seen,fp_add(seen,value)); } while(old!=seen);
}
__device__ void reduce(c71_linear::Result value,c71_linear::Result* output) {
    __shared__ c71_linear::Result partial[c71_linear::threads];
    partial[threadIdx.x]=value;
    __syncthreads();
    for(unsigned stride=c71_linear::threads/2;stride;stride/=2) {
        if(threadIdx.x<stride) partial[threadIdx.x]=c71_linear::sum(partial[threadIdx.x],partial[threadIdx.x+stride]);
        __syncthreads();
    }
    if(threadIdx.x==0) for(unsigned i=0;i<5;++i) {
        atomic_field(&output->values[i].c0,partial[0].values[i].c0);
        atomic_field(&output->values[i].c1,partial[0].values[i].c1);
        atomic_field(&output->values[i].c2,partial[0].values[i].c2);
    }
}
__global__ void weight_kernel(const int16_t* input,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t first,uint64_t count,
    c71_linear::Shape shape,const c71_linear::Chunk* chunks,const Fp3* tables,
    const c71_linear::Group* groups,const c71_linear::Interval* intervals,const Fp3* points,
    c71_linear::Result* output,uint32_t* flag) {
    c71_linear::Result value{};
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t address=c71_pcs::packed_address(tiles,tile_count,first+i,shape.live);
        const int16_t original=input[address];
        if(original==INT16_MIN) { atomicExch(flag,1u); continue; }
        const uint64_t scalar=original<0 ? P-uint64_t(-int32_t(original)) : uint64_t(original);
        value=c71_linear::sum(value,c71_linear::contribution(first+i,scalar,shape,chunks,tables,groups,intervals,points));
    }
    reduce(value,output);
}
__global__ void source_kernel(const void* input,unsigned kind,c71_pcs::SourceTile tile,
    c71_linear::Shape shape,const c71_linear::Chunk* chunks,const Fp3* tables,
    const c71_linear::Group* groups,const c71_linear::Interval* intervals,const Fp3* points,
    c71_linear::Result* output,uint32_t* flag) {
    c71_linear::Result value{};
    const uint64_t words=tile.rows*tile.columns;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<words;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t address=tile.input_first+(i/tile.columns)*tile.input_stride+i%tile.columns;
        const int64_t original=kind==1 ? static_cast<const int16_t*>(input)[address] : static_cast<const int64_t*>(input)[address];
        for(unsigned lane=0;lane<tile.width;++lane) {
            uint8_t byte=0;
            if(!c71_byte::encode(original,tile.signed_width,tile.byte_first+lane,byte)) { atomicExch(flag,1u); continue; }
            const uint64_t index=tile.original_first+i*tile.width+lane;
            value=c71_linear::sum(value,c71_linear::contribution(index,byte,shape,chunks,tables,groups,intervals,points));
        }
    }
    reduce(value,output);
}
unsigned blocks(uint64_t count) {
    const uint64_t required=(count+c71_linear::threads-1)/c71_linear::threads;
    return unsigned(required<c71_linear::max_blocks ? required : c71_linear::max_blocks);
}
}

extern "C" cudaError_t c71_linear_weights_launch(cudaStream_t stream,const int16_t* input,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t first,uint64_t count,
    c71_linear::Shape shape,const c71_linear::Chunk* chunks,
    const Fp3* tables,const c71_linear::Group* groups,const c71_linear::Interval* intervals,
    const Fp3* points,c71_linear::Result* output,uint32_t* flag) {
    if(!stream || !input || !tiles || !tile_count || !output || !flag || !c71_linear::valid(shape) || !count ||
       first>shape.live || count>shape.live-first) return cudaErrorInvalidValue;
    weight_kernel<<<blocks(count),c71_linear::threads,0,stream>>>(input,tiles,tile_count,first,count,shape,chunks,tables,groups,intervals,points,output,flag);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_linear_source_launch(cudaStream_t stream,const void* input,unsigned kind,
    c71_pcs::SourceTile tile,c71_linear::Shape shape,const c71_linear::Chunk* chunks,const Fp3* tables,
    const c71_linear::Group* groups,const c71_linear::Interval* intervals,const Fp3* points,
    c71_linear::Result* output,uint32_t* flag) {
    if(!stream || !input || !output || !flag || !c71_linear::valid(shape) || (kind!=1 && kind!=6) || !tile.rows || !tile.columns ||
       !tile.width || tile.original_first>=shape.live || tile.rows>(shape.live-tile.original_first)/tile.width/tile.columns)
        return cudaErrorInvalidValue;
    source_kernel<<<blocks(tile.rows*tile.columns),c71_linear::threads,0,stream>>>(input,kind,tile,shape,chunks,tables,groups,intervals,points,output,flag);
    return cudaGetLastError();
}

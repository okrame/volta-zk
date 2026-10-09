// One original scan per phase, on the caller's common stream. No allocation,
// owner, host download, FFT, Merkle, transcript or fallback is introduced.
#include <cuda_runtime.h>
#include "c71_pcs_residual.cuh"

namespace {
namespace pcs=c71_pcs_residual;
__device__ void atomic_field(uint64_t* address,uint64_t value) {
    auto* pointer=reinterpret_cast<unsigned long long*>(address);
    unsigned long long old=atomicCAS(pointer,0ULL,0ULL),seen;
    do { seen=old; old=atomicCAS(pointer,seen,fp_add(seen,value)); } while(old!=seen);
}
__device__ void atomic_e(pcs::E* address,pcs::E value) {
    atomic_field(&address->c0,value.c0); atomic_field(&address->c1,value.c1); atomic_field(&address->c2,value.c2);
}
template<pcs::Phase phase> __device__ pcs::E* scratch() {
    if constexpr(phase==pcs::Phase::singleton) {
        __shared__ pcs::E buckets[pcs::singleton_capacity];
        return buckets;
    } else if constexpr(phase==pcs::Phase::ood) {
        __shared__ pcs::E partial[pcs::threads];
        return partial;
    } else return nullptr;
}
template<pcs::Phase phase> __device__ void begin(pcs::E* shared) {
    if constexpr(phase==pcs::Phase::singleton) {
        for(unsigned i=threadIdx.x;i<pcs::singleton_capacity;i+=blockDim.x) shared[i]={};
        __syncthreads();
    }
}
__device__ bool checked_lookup(uint64_t index,const pcs::Chunk* chunks,unsigned count,
    const pcs::E* tables,pcs::E& out,uint32_t* flag) {
    out={1,0,0};
    for(unsigned i=0;i<count;++i) {
        const auto c=chunks[i];
        const pcs::E value=tables[c.first+((index>>c.shift)&((uint64_t{1}<<c.bits)-1))];
        if(!pcs::canonical(value)) { atomicExch(flag,1u); return false; }
        out=pcs::mul(out,value);
    }
    return true;
}
template<pcs::Phase phase> __device__ void contribute(uint64_t index,uint64_t original,
    pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,pcs::Output output,
    pcs::CosetShape cosets,const uint64_t* high,pcs::PowerShape powers,const pcs::E* power_low,
    const pcs::E* power_high,pcs::E* shared,pcs::E& reduced,uint32_t* flag) {
    pcs::E weight{};
    const uint64_t folded=pcs::folded_index(index,shape);
    const uint64_t equality_index=phase==pcs::Phase::singleton ? folded : index>>shape.remaining;
    if(!checked_lookup(equality_index,chunks,shape.equality.chunks,tables,weight,flag)) return;
    const pcs::E value=pcs::base_mul(weight,original);
    if(pcs::zero(value)) return; // Original visit is still counted by the caller.
    if constexpr(phase==pcs::Phase::singleton) {
        atomic_e(shared+(index>>shape.remaining),value);
    } else if constexpr(phase==pcs::Phase::retention) {
        atomic_field(output.retained.c0+folded,value.c0);
        atomic_field(output.retained.c1+folded,value.c1);
        atomic_field(output.retained.c2+folded,value.c2);
    } else if constexpr(phase==pcs::Phase::cosets) {
        const uint64_t n=uint64_t{1}<<(shape.remaining-2),within=folded%n;
        const unsigned column=unsigned(folded/n);
        const uint64_t row=within%cosets.rows,q=within/cosets.rows;
        // Every decoded original updates all three limbs and both cosets;
        // neither limb nor column may cause another producer replay.
        for(unsigned lane=0;lane<2;++lane) {
            const uint64_t factor=high[q*2+lane];
            if(factor>=P) { atomicExch(flag,1u); continue; }
            const pcs::E current=pcs::base_mul(value,factor);
            for(unsigned component=0;component<3;++component)
                atomic_field(output.ring+pcs::ring_index(column,component,lane,row,cosets),pcs::limb(current,component));
        }
    } else if constexpr(phase==pcs::Phase::ood) {
        const pcs::E lo=power_low[folded&(pcs::low_count(powers)-1)],hi=power_high[folded>>powers.low_bits];
        if(!pcs::canonical(lo) || !pcs::canonical(hi)) { atomicExch(flag,1u); return; }
        reduced=pcs::add(reduced,pcs::mul(value,pcs::mul(lo,hi)));
    }
}
template<pcs::Phase phase> __device__ void finish(pcs::E* shared,pcs::E reduced,pcs::Output output) {
    if constexpr(phase==pcs::Phase::singleton) {
        __syncthreads();
        for(unsigned i=threadIdx.x;i<pcs::singleton_capacity;i+=blockDim.x) atomic_e(output.reduced+i,shared[i]);
    } else if constexpr(phase==pcs::Phase::ood) {
        shared[threadIdx.x]=reduced;
        __syncthreads();
        for(unsigned stride=pcs::threads/2;stride;stride/=2) {
            if(threadIdx.x<stride) shared[threadIdx.x]=pcs::add(shared[threadIdx.x],shared[threadIdx.x+stride]);
            __syncthreads();
        }
        if(threadIdx.x==0) atomic_e(output.reduced,shared[0]);
    }
}
template<pcs::Phase phase> __global__ void weights(const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t first,uint64_t count,pcs::Shape shape,
    const pcs::Chunk* chunks,const pcs::E* tables,pcs::Output output,pcs::CosetShape cosets,
    const uint64_t* high,pcs::PowerShape powers,const pcs::E* power_low,const pcs::E* power_high,uint32_t* flag) {
    pcs::E* shared=scratch<phase>();
    begin<phase>(shared);
    pcs::E reduced{};
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t index=first+i,address=c71_pcs::packed_address(tiles,tile_count,index,shape.live);
        if(address>=input_words) { atomicExch(flag,1u); continue; }
        uint64_t original=0;
        if(!pcs::weight_scalar(input[address],original)) { atomicExch(flag,1u); continue; }
        contribute<phase>(index,original,shape,chunks,tables,output,cosets,high,powers,power_low,power_high,shared,reduced,flag);
    }
    finish<phase>(shared,reduced,output);
}
template<pcs::Phase phase> __global__ void source(const void* input,unsigned kind,c71_pcs::SourceTile tile,
    pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,pcs::Output output,
    pcs::CosetShape cosets,const uint64_t* high,pcs::PowerShape powers,const pcs::E* power_low,
    const pcs::E* power_high,uint32_t* flag) {
    pcs::E* shared=scratch<phase>();
    begin<phase>(shared);
    pcs::E reduced{};
    const uint64_t words=tile.rows*tile.columns;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<words;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t address=tile.input_first+(i/tile.columns)*tile.input_stride+i%tile.columns;
        const int64_t original=kind==1 ? static_cast<const int16_t*>(input)[address] : static_cast<const int64_t*>(input)[address];
        for(unsigned lane=0;lane<tile.width;++lane) {
            uint8_t byte=0;
            if(!c71_byte::encode(original,tile.signed_width,tile.byte_first+lane,byte)) { atomicExch(flag,1u); continue; }
            const uint64_t index=tile.original_first+i*tile.width+lane;
            contribute<phase>(index,byte,shape,chunks,tables,output,cosets,high,powers,power_low,power_high,shared,reduced,flag);
        }
    }
    finish<phase>(shared,reduced,output);
}
__global__ void coset_powers(uint64_t* low,uint64_t* high,pcs::Shape shape,pcs::CosetShape cosets,uint64_t omega) {
    const uint64_t count=2*cosets.rows>2*pcs::high_rows(shape,cosets) ? 2*cosets.rows : 2*pcs::high_rows(shape,cosets);
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        if(i<2*cosets.rows) low[i]=c71_pcs::power(omega,uint64_t(cosets.first_coset+i/cosets.rows)*(i%cosets.rows));
        if(i<2*pcs::high_rows(shape,cosets)) high[i]=c71_pcs::power(omega,uint64_t(cosets.first_coset+i%2)*(i/2)*cosets.rows);
    }
}
__global__ void ood_powers(pcs::E* low,pcs::E* high,pcs::PowerShape p,pcs::E point) {
    const uint64_t count=pcs::low_count(p)>pcs::high_count(p) ? pcs::low_count(p) : pcs::high_count(p);
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        if(i<pcs::low_count(p)) low[i]=pcs::power(point,i);
        if(i<pcs::high_count(p)) high[i]=pcs::power(point,i<<p.low_bits);
    }
}
__global__ void pad(uint64_t* ring,const pcs::E* pads,const uint64_t* low,const uint64_t* high,
    pcs::Shape shape,pcs::CosetShape cosets,uint32_t* flag) {
    const uint64_t n=uint64_t{1}<<(shape.remaining-2);
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<24*cosets.rows;i+=uint64_t(gridDim.x)*blockDim.x) {
        const unsigned base_column=unsigned(i/(2*cosets.rows)),column=base_column/3,component=base_column%3;
        const unsigned lane=unsigned((i/cosets.rows)%2);
        const uint64_t row=i%cosets.rows;
        bool valid=ring[i]<P && low[uint64_t(lane)*cosets.rows+row]<P;
        for(uint64_t j=(row+cosets.rows-(n%cosets.rows))%cosets.rows;j<cosets.pad_rows;j+=cosets.rows)
            valid=valid && pcs::canonical(pads[uint64_t(column)*cosets.pad_rows+j]) && high[((n+j)/cosets.rows)*2+lane]<P;
        if(!valid) { atomicExch(flag,1u); continue; }
        ring[i]=pcs::padded(ring[i],pads,low,high,shape,cosets,column,component,row,lane);
    }
}
__global__ void fold_kernel(pcs::ConstPlanes input,pcs::Planes output,uint64_t count,unsigned rounds,
    pcs::E r0,pcs::E r1,uint32_t* flag) {
    const uint64_t size=count>>rounds;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<size;i+=uint64_t(gridDim.x)*blockDim.x) {
        bool valid=true;
        for(unsigned j=0;j<(1u<<rounds);++j) valid=valid && pcs::canonical(pcs::load(input,i+j*size));
        if(!valid) { atomicExch(flag,1u); continue; }
        pcs::store(output,i,pcs::folded_at(input,count,i,rounds,r0,r1));
    }
}
unsigned blocks(uint64_t count) {
    const uint64_t needed=(count+pcs::threads-1)/pcs::threads;
    return unsigned(needed<pcs::max_blocks ? needed : pcs::max_blocks);
}
}

extern "C" cudaError_t c71_pcs_residual_weights_launch(cudaStream_t stream,const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t first,uint64_t count,
    pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,pcs::Phase phase,pcs::Output output,
    pcs::CosetShape cosets,const uint64_t* high,pcs::PowerShape powers,const pcs::E* power_low,const pcs::E* power_high,uint32_t* flag) {
    if(!stream || !input || !input_words || !tiles || !tile_count || !flag || !count || first>shape.live || count>shape.live-first ||
       !pcs::valid_arguments(shape,phase,output,chunks,tables,cosets,high,powers,power_low,power_high)) return cudaErrorInvalidValue;
#define C71_RESIDUAL_WEIGHT_CASE(PHASE) case pcs::Phase::PHASE: \
    weights<pcs::Phase::PHASE><<<blocks(count),pcs::threads,0,stream>>>(input,input_words,tiles,tile_count,first,count,shape,chunks,tables,output,cosets,high,powers,power_low,power_high,flag); break
    switch(phase) {
        C71_RESIDUAL_WEIGHT_CASE(singleton);
        C71_RESIDUAL_WEIGHT_CASE(retention);
        C71_RESIDUAL_WEIGHT_CASE(cosets);
        C71_RESIDUAL_WEIGHT_CASE(ood);
        default: return cudaErrorInvalidValue;
    }
#undef C71_RESIDUAL_WEIGHT_CASE
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_source_launch(cudaStream_t stream,const void* input,uint64_t input_words,
    unsigned kind,c71_pcs::SourceTile tile,pcs::Shape shape,const pcs::Chunk* chunks,const pcs::E* tables,
    pcs::Phase phase,pcs::Output output,pcs::CosetShape cosets,const uint64_t* high,
    pcs::PowerShape powers,const pcs::E* power_low,const pcs::E* power_high,uint32_t* flag) {
    if(!stream || !input || !flag || !c71_pcs::valid(tile,kind,input_words,shape.live) ||
       !pcs::valid_arguments(shape,phase,output,chunks,tables,cosets,high,powers,power_low,power_high)) return cudaErrorInvalidValue;
#define C71_RESIDUAL_SOURCE_CASE(PHASE) case pcs::Phase::PHASE: \
    source<pcs::Phase::PHASE><<<blocks(tile.rows*tile.columns),pcs::threads,0,stream>>>(input,kind,tile,shape,chunks,tables,output,cosets,high,powers,power_low,power_high,flag); break
    switch(phase) {
        C71_RESIDUAL_SOURCE_CASE(singleton);
        C71_RESIDUAL_SOURCE_CASE(retention);
        C71_RESIDUAL_SOURCE_CASE(cosets);
        C71_RESIDUAL_SOURCE_CASE(ood);
        default: return cudaErrorInvalidValue;
    }
#undef C71_RESIDUAL_SOURCE_CASE
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_coset_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,
    pcs::Shape shape,pcs::CosetShape cosets) {
    if(!stream || !low || !high || low==high || !pcs::valid(cosets,shape)) return cudaErrorInvalidValue;
    const uint64_t count=2*cosets.rows>2*pcs::high_rows(shape,cosets) ? 2*cosets.rows : 2*pcs::high_rows(shape,cosets);
    const uint64_t omega=c71_pcs::power(7,(P-1)/(cosets.rows*cosets.cosets));
    coset_powers<<<blocks(count),pcs::threads,0,stream>>>(low,high,shape,cosets,omega);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_ood_powers_launch(cudaStream_t stream,pcs::E* low,pcs::E* high,
    pcs::PowerShape powers,pcs::E point) {
    if(!stream || !low || !high || low==high || !pcs::valid(powers) || !pcs::canonical(point)) return cudaErrorInvalidValue;
    const uint64_t count=pcs::low_count(powers)>pcs::high_count(powers) ? pcs::low_count(powers) : pcs::high_count(powers);
    ood_powers<<<blocks(count),pcs::threads,0,stream>>>(low,high,powers,point);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_pad_launch(cudaStream_t stream,uint64_t* ring,const pcs::E* pads,
    const uint64_t* low,const uint64_t* high,pcs::Shape shape,pcs::CosetShape cosets,uint32_t* flag) {
    if(!stream || !ring || !pads || !low || !high || low==high || ring==low || ring==high || !flag ||
       !pcs::valid(cosets,shape)) return cudaErrorInvalidValue;
    pad<<<blocks(24*cosets.rows),pcs::threads,0,stream>>>(ring,pads,low,high,shape,cosets,flag);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_residual_fold_launch(cudaStream_t stream,pcs::ConstPlanes input,pcs::Planes output,
    uint64_t count,unsigned rounds,pcs::E r0,pcs::E r1,uint32_t* flag) {
    const uint64_t* sources[]={input.c0,input.c1,input.c2};
    const uint64_t* targets[]={output.c0,output.c1,output.c2};
    if(!stream || !flag || !pcs::valid_fold(count,rounds,r0,r1)) return cudaErrorInvalidValue;
    for(unsigned i=0;i<3;++i) {
        if(!sources[i] || !targets[i]) return cudaErrorInvalidValue;
        for(unsigned j=0;j<3;++j) if(targets[i]==sources[j] || (i!=j && (sources[i]==sources[j] || targets[i]==targets[j]))) return cudaErrorInvalidValue;
    }
    fold_kernel<<<blocks(count>>rounds),pcs::threads,0,stream>>>(input,output,count,rounds,r0,r1,flag);
    return cudaGetLastError();
}

// Native bounded range kernels for the canopy/Gram/retention evaluator.
// A launch adapter must validate geometry, own/account buffers and synchronize
// errors BEFORE Rust authenticates outputs. These kernels do not admit a run.
#include <cuda_runtime.h>
#include "c71_range_native.cuh"
using namespace c71_range;

// Exactly 256 threads. Shared Pair storage is allocated for the ACTUAL group,
// at most 1024 pairs (49,152 bytes), not a full-domain expansion of the reader.
template<class T>
__device__ void subtree_pairs(const T* input, Pair* nodes, unsigned pairs,
                             unsigned child_pairs, Fp3 alpha) {
    for(unsigned i=threadIdx.x;i<pairs;i+=256)
        nodes[i]=leaf_pair(input[2*i],input[2*i+1],alpha);
    __syncthreads();
    // Strided roots avoid the cross-thread overwrite of an in-place compact
    // reduction. Child subtrees never merge across their public boundary.
    for(unsigned stride=1;stride<child_pairs;stride*=2) {
        for(unsigned i=threadIdx.x;i<pairs/(2*stride);i+=256) {
            const unsigned j=i*2*stride;
            nodes[j]=merge(nodes[j],nodes[j+stride]);
        }
        __syncthreads();
    }
}

template<class T>
__device__ void roots(const T* input, size_t groups, unsigned bottom, Fp3 alpha, Pair* out) {
    if(blockIdx.x>=groups) return;
    extern __shared__ __align__(8) unsigned char memory[];
    Pair* nodes=reinterpret_cast<Pair*>(memory);
    const unsigned words=1u<<bottom;
    subtree_pairs(input+size_t(blockIdx.x)*words,nodes,words/2,words/2,alpha);
    if(threadIdx.x==0) out[blockIdx.x]=nodes[0];
}
extern "C" __global__ void c71_range_roots_u8(const uint8_t* in,size_t n,unsigned b,Fp3 a,Pair* out) {
    roots(in,n,b,a,out);
}
extern "C" __global__ void c71_range_roots_i16(const int16_t* in,size_t n,unsigned b,Fp3 a,Pair* out) {
    roots(in,n,b,a,out);
}
extern "C" __global__ void c71_range_canopy(const Pair* in,Pair* out,size_t n) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<n) out[i]=merge(in[2*i],in[2*i+1]);
}

__device__ void atomic_field(uint64_t* address,uint64_t value) {
    auto* p=reinterpret_cast<unsigned long long*>(address);
    unsigned long long old=atomicCAS(p,0,0), seen;
    do { seen=old; old=atomicCAS(p,seen,fp_add(seen,value)); } while(old!=seen);
}
__device__ void atomic_field(Fp3* p,Fp3 value) {
    atomic_field(&p->c0,value.c0); atomic_field(&p->c1,value.c1); atomic_field(&p->c2,value.c2);
}

// Each CTA contracts one complete [old prefix][u][subtree] group. The selected
// schedule bounds this group by 2^11 original words even for D34/D35. Only H
// buckets or retained children leave shared memory; no full lower child tree.
template<class T>
__device__ void groups(const T* input,size_t tails,Group g,Children* retained,Fp3* h) {
    if(blockIdx.x>=tails) return;
    const unsigned length=1u<<g.width, old_count=1u<<g.prefix_bits;
    const unsigned subtree=1u<<g.bottom, words=length*old_count*subtree;
    extern __shared__ __align__(8) unsigned char memory[];
    Pair* nodes=reinterpret_cast<Pair*>(memory);
    const unsigned pair_count=g.bottom==1 ? 0:words/2;
    Children* bucket=reinterpret_cast<Children*>(nodes+pair_count);
    input+=size_t(blockIdx.x)*words;
    if(g.bottom>1) subtree_pairs(input,nodes,pair_count,subtree/4,g.alpha);
    for(unsigned u=threadIdx.x;u<length;u+=256) {
        Children value{};
        for(unsigned old=0;old<old_count;++old) {
            const unsigned start=(old*length+u)*subtree;
            Children child{};
            if(g.bottom==1) {
                child={{Fp3{1,0,0},sub(g.alpha,integer(input[start])),
                        Fp3{1,0,0},sub(g.alpha,integer(input[start+1]))}};
            } else {
                const Pair a=nodes[start/2],b=nodes[start/2+subtree/4];
                child={{a.p,a.q,b.p,b.q}};
            }
            const Fp3 weight=equality(g.prefix,g.prefix_bits,old);
            for(unsigned j=0;j<4;++j) value.v[j]=add(value.v[j],mul6(weight,child.v[j]));
        }
        bucket[u]=value;
    }
    __syncthreads();
    const size_t tail=g.first_tail+blockIdx.x;
    if(g.width==0) {
        if(threadIdx.x==0) retained[tail]=bucket[0];
        return;
    }
    const Fp3 weight=equality(g.tail_point,g.tail_bits,tail);
    const size_t offset=(tail%g.buckets)*length*length;
    // ponytail: bounded bucket CAS reduction; contention must be measured
    // before admission, then replace with a hierarchical reduction if needed.
    for(unsigned cell=threadIdx.x;cell<length*length;cell+=256)
        atomic_field(h+offset+cell,gram(bucket[cell/length],bucket[cell%length],g.lambda,weight));
}
extern "C" __global__ void c71_range_groups_u8(const uint8_t* in,size_t n,Group g,Children* c,Fp3* h) {
    groups(in,n,g,c,h);
}
extern "C" __global__ void c71_range_groups_i16(const int16_t* in,size_t n,Group g,Children* c,Fp3* h) {
    groups(in,n,g,c,h);
}

extern "C" __global__ void c71_range_h_sum(const Fp3* buckets,Fp3* out,unsigned cells,unsigned count) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=cells) return;
    Fp3 sum{};
    for(unsigned b=0;b<count;++b) sum=add(sum,buckets[size_t(b)*cells+i]);
    out[i]=sum;
}
// Distinct small input/output buffers: compacting H in parallel in-place races.
extern "C" __global__ void c71_range_h_fold(const Fp3* in,Fp3* out,unsigned half,Fp3 r) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=half*half) return;
    const unsigned row=i/half,col=i%half,n=2*half;
    out[i]=fold(fold(in[row*n+col],in[row*n+col+half],r),
                fold(in[(row+half)*n+col],in[(row+half)*n+col+half],r),r);
}
extern "C" __global__ void c71_range_child_fold(Children* in,size_t half,Fp3 r) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<half) in[i]=fold(in[i],in[i+half],r);
}
__device__ void reduce(Cubic value,Cubic* out) {
    __shared__ Cubic values[256];
    values[threadIdx.x]=value;
    __syncthreads();
    for(unsigned offset=128;offset;offset/=2) {
        if(threadIdx.x<offset) values[threadIdx.x]=sum(values[threadIdx.x],values[threadIdx.x+offset]);
        __syncthreads();
    }
    if(threadIdx.x==0) out[blockIdx.x]=values[0];
}
extern "C" __global__ void c71_range_coefficients(const Children* in,size_t half,Round r,Cubic* out) {
    const size_t i=size_t(blockIdx.x)*256+threadIdx.x;
    Cubic value{};
    if(i<half) {
        const Fp3 e0=mul6(r.prefix_equality,equality(r.point,r.bits,i));
        const Fp3 e1=mul6(r.prefix_equality,equality(r.point,r.bits,i+half));
        value=coefficients(in[i],in[i+half],r.lambda,e0,e1);
    }
    reduce(value,out);
}
extern "C" __global__ void c71_range_reduce(const Cubic* in,size_t n,Cubic* out) {
    const size_t i=size_t(blockIdx.x)*256+threadIdx.x;
    reduce(i<n?in[i]:Cubic{},out);
}
extern "C" __global__ void c71_range_h_coefficients(const Fp3* h,unsigned half,Round r,Cubic* out) {
    if(blockIdx.x==0 && threadIdx.x==0) *out=h_coefficients(h,half,r);
}

// Runtime entry points for the subsequent resident-buffer adapter. No memory
// allocation, CPU fallback, implicit default stream, or explicit stream barrier.
// cudaGetLastError checks launch failures only; completion must be fenced by
// the owning context before coefficients are downloaded/authenticated.
extern "C" cudaError_t c71_range_launch_roots(cudaStream_t stream,unsigned signed_words,
    const void* input,size_t words,unsigned bottom,Fp3 alpha,Pair* out,size_t roots_count) {
    const size_t cap=signed_words?size_t{1}<<27:size_t{1}<<31;
    if(!stream || signed_words>1 || !input || !out || !words || words>cap || bottom<1 || bottom>11 ||
       words%(size_t{1}<<bottom) || roots_count!=words/(size_t{1}<<bottom) ||
       alpha.c0>=P || alpha.c1>=P || alpha.c2>=P) return cudaErrorInvalidValue;
    const size_t shared=(size_t{1}<<(bottom-1))*sizeof(Pair);
    if(signed_words)
        c71_range_roots_i16<<<roots_count,256,shared,stream>>>(static_cast<const int16_t*>(input),roots_count,bottom,alpha,out);
    else
        c71_range_roots_u8<<<roots_count,256,shared,stream>>>(static_cast<const uint8_t*>(input),roots_count,bottom,alpha,out);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_range_launch_groups(cudaStream_t stream,unsigned signed_words,
    const void* input,size_t words,Group g,Children* retained,size_t retained_count,Fp3* h,size_t h_count) {
    const size_t shared=group_shared_bytes(g,1);
    if(!stream || signed_words>1 || !input || !shared) return cudaErrorInvalidValue;
    const size_t group_words=size_t{1}<<(g.bottom+g.prefix_bits+g.width);
    const size_t tails=words/group_words,cap=signed_words?size_t{1}<<27:size_t{1}<<31;
    if(!words || words>cap || words%group_words || !group_shared_bytes(g,tails) ||
       (g.width==0 ? (!retained || retained_count<g.first_tail+tails) :
        (!h || h_count!=size_t(g.buckets)*(size_t{1}<<(2*g.width))))) return cudaErrorInvalidValue;
    if(g.alpha.c0>=P || g.alpha.c1>=P || g.alpha.c2>=P ||
       g.lambda.c0>=P || g.lambda.c1>=P || g.lambda.c2>=P) return cudaErrorInvalidValue;
    for(unsigned i=0;i<g.prefix_bits;++i)
        if(g.prefix[i].c0>=P || g.prefix[i].c1>=P || g.prefix[i].c2>=P) return cudaErrorInvalidValue;
    for(unsigned i=0;i<g.tail_bits;++i)
        if(g.tail_point[i].c0>=P || g.tail_point[i].c1>=P || g.tail_point[i].c2>=P) return cudaErrorInvalidValue;
    // Groups including children can slightly exceed the default 48 KiB.
    // Keep the FUNCTION-wide limit constant across concurrent contexts; the
    // actual per-launch shared request remains `shared` below.
    cudaError_t status=signed_words
        ? cudaFuncSetAttribute(c71_range_groups_i16,cudaFuncAttributeMaxDynamicSharedMemorySize,52224)
        : cudaFuncSetAttribute(c71_range_groups_u8,cudaFuncAttributeMaxDynamicSharedMemorySize,52224);
    if(status!=cudaSuccess) return status;
    if(signed_words)
        c71_range_groups_i16<<<tails,256,shared,stream>>>(static_cast<const int16_t*>(input),tails,g,retained,h);
    else
        c71_range_groups_u8<<<tails,256,shared,stream>>>(static_cast<const uint8_t*>(input),tails,g,retained,h);
    return cudaGetLastError();
}

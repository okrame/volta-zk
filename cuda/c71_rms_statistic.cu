#include <cuda_runtime.h>
#include "c71_rms_statistic.cuh"
namespace c71_rms_statistic {
namespace {
using namespace c71_range;
__device__ Fp3 factor(const Fp3* p,unsigned bits,unsigned i) {
    const unsigned low=bits-bits/2;
    return mul6(p[i>>low],p[(1u<<(bits/2))+(i&((1u<<low)-1))]);
}
__global__ void eq_factors(const Fp3* point,unsigned bits,Fp3* out) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x,high=bits/2,low=bits-high;
    if(i<(1u<<high))out[i]=equality(point,high,i);
    if(i<(1u<<low))out[(1u<<high)+i]=equality(point+high,low,i);
}
__device__ Fp3 original(Shape s,const uint8_t* source,unsigned i) {
    const unsigned row=i>>s.column_bits,col=i&((1u<<s.column_bits)-1);
    if(row>=s.rows || col>=s.columns)return {};
    const uint64_t at=(uint64_t(row)*s.columns+col)*2;
    const int word=int(source[at])+(int(source[at+1])<<8);
    return integer(word>=32768?word-65536:word);
}
__device__ Fp3 regenerated(Shape s,const uint8_t* source,const Fp3* eq,unsigned key) {
    Fp3 value{};const unsigned width=1u<<(s.bits-s.round);
    for(unsigned i=0;i<(1u<<s.round);++i)value=add(value,mul6(factor(eq,s.round,i),original(s,source,i*width+key)));
    return value;
}
__global__ void regenerate_rows(Shape s,const uint8_t* source,const Fp3* eq,unsigned first,unsigned n,Fp3* state) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i<n)state[first+i]=regenerated(s,source,eq,first+i);
}
__global__ void fold_rows(unsigned rows,Fp3 r,Fp3* state) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x,half=rows/2;
    if(i<half)state[i]=fold(state[i],state[i+half],r);
}
__global__ void square_pairs(Shape s,const uint8_t* source,const Fp3* meta,
    const Fp3* peq,const Fp3* seq,const Fp3* state,unsigned first,unsigned n,Fp3* partials) {
    __shared__ Cubic sums[128];const unsigned i=blockIdx.x*128+threadIdx.x;
    Cubic value{};
    if(i<n) {
        const unsigned key=first+i,half=1u<<(s.bits-s.round-1);
        const auto a=s.round<s.checkpoint?regenerated(s,source,peq,key):state[key];
        const auto b=s.round<s.checkpoint?regenerated(s,source,peq,key+half):state[key+half];
        Fp3 fixed{1,0,0};
        for(unsigned j=0;j<s.round;++j)
            fixed=mul6(fixed,add(mul6(sub(Fp3{1,0,0},meta[j]),sub(Fp3{1,0,0},meta[prefix+j])),mul6(meta[j],meta[prefix+j])));
        const auto suffix=mul6(fixed,factor(seq,s.bits-s.round-1,key));
        const auto lo=mul6(suffix,sub(Fp3{1,0,0},meta[s.round])),hi=mul6(suffix,meta[s.round]);
        // Original fraction-tree primitive: (0,X,0,X), lambda=1 is X².
        Children left{{{},a,{},a}},right{{{},b,{},b}};
        value=c71_range::coefficients(left,right,Fp3{1,0,0},lo,hi);
    }
    sums[threadIdx.x]=value;__syncthreads();
    for(unsigned step=64;step;step/=2) {if(threadIdx.x<step)sums[threadIdx.x]=sum(sums[threadIdx.x],sums[threadIdx.x+step]);__syncthreads();}
    if(!threadIdx.x)for(unsigned j=0;j<4;++j)partials[uint64_t(blockIdx.x)*4+j]=sums[0].c[j];
}
__global__ void sum_partials(const Fp3* partials,unsigned n,Fp3* out) {
    __shared__ Fp3 values[128];const unsigned tid=threadIdx.x,c=blockIdx.x;Fp3 v{};
    for(unsigned i=tid;i<n;i+=128)v=add(v,partials[uint64_t(i)*4+c]);
    values[tid]=v;__syncthreads();
    for(unsigned step=64;step;step/=2) {if(tid<step)values[tid]=add(values[tid],values[tid+step]);__syncthreads();}
    if(!tid)out[c]=add(out[c],values[0]);
}
}
cudaError_t factors(cudaStream_t stream,const Fp3* p,unsigned bits,Fp3* out) {
    eq_factors<<<((1u<<(bits-bits/2))+127)/128,128,0,stream>>>(p,bits,out);return cudaGetLastError();
}
cudaError_t regenerate(cudaStream_t stream,Shape s,const uint8_t* source,const Fp3* eq,unsigned first,unsigned n,Fp3* state) {
    regenerate_rows<<<(n+127)/128,128,0,stream>>>(s,source,eq,first,n,state);return cudaGetLastError();
}
cudaError_t fold_state(cudaStream_t stream,unsigned rows,Fp3 r,Fp3* state) {
    fold_rows<<<(rows/2+127)/128,128,0,stream>>>(rows,r,state);return cudaGetLastError();
}
cudaError_t coefficients(cudaStream_t stream,Shape s,const uint8_t* source,const Fp3* meta,const Fp3* peq,const Fp3* seq,const Fp3* state,unsigned first,unsigned n,Fp3* out) {
    square_pairs<<<(n+127)/128,128,0,stream>>>(s,source,meta,peq,seq,state,first,n,out);return cudaGetLastError();
}
cudaError_t reduce(cudaStream_t stream,const Fp3* p,unsigned n,Fp3* out) {
    sum_partials<<<4,128,0,stream>>>(p,n,out);return cudaGetLastError();
}
}

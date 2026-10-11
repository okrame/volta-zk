#include <cuda_runtime.h>
#include <algorithm>
#include "c71_rms_index.cuh"
namespace c71_rms_index {
using namespace c71_range;
namespace {
__global__ void bind_selectors(unsigned count,unsigned programs,c71_rms_prefix::Gate* gates,
    const c71_rms_prefix::GateRange* ranges,const Fp3* selectors) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
    unsigned lo=0,hi=programs;
    while(lo<hi) {const auto mid=lo+(hi-lo)/2;if(ranges[mid].first+ranges[mid].count<=i)lo=mid+1;else hi=mid;}
    gates[i].weight=mul6(gates[i].weight,selectors[lo]);
}
__global__ void advance_state(unsigned count,unsigned half,bool right,const Fp3* point,
    c71_rms_prefix::Gate* gates,Fp3* vector) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;const auto r=point[0];
    if(i<count) {auto& g=gates[i];g.weight=mul6(g.weight,((right?g.y:g.x)&half)?r:sub(Fp3{1,0,0},r));}
    if(i<half)vector[i]=fold(vector[i],vector[i+half],r);
}
__global__ void save_left(Fp3* scratch,const Fp3* vector) {scratch[3]=vector[0];}
__device__ void polynomial(unsigned op,Fp3 x,Fp3 dx,Fp3 y,Fp3 dy,Fp3* v) {
    if(op==2) {v[0]=x;v[1]=dx;return;}
    v[0]=mul6(x,y);v[1]=add(mul6(x,dy),mul6(dx,y));v[2]=mul6(dx,dy);
    if(op==1) {v[0]=sub(add(x,y),add(v[0],v[0]));v[1]=sub(add(dx,dy),add(v[1],v[1]));v[2]=sub(Fp3{},add(v[2],v[2]));}
}
__global__ void gate_coefficients(unsigned count,unsigned width,unsigned original_width,bool right,bool terminal,
    const c71_rms_prefix::Gate* gates,const Fp3* values,Fp3* scratch) {
    __shared__ Fp3 sum[3][threads];
    const unsigned tid=threadIdx.x,i=blockIdx.x*threads+tid,half=width/2;
    Fp3 c[3]{};
    if(i<count) {
        const auto g=gates[i];
        if(terminal) {
            if(g.op==0)c[2]=g.weight;
            else if(g.op==1) {c[0]=c[1]=g.weight;c[2]=sub(Fp3{},add(g.weight,g.weight));}
            else c[0]=g.weight;
        } else {
            const unsigned index=right?g.y:g.x,at=index%half;
            const auto* active=values+original_width;
            const auto a=active[at],d=sub(active[at+half],a);
            Fp3 f[3]{};
            if(right)polynomial(g.op,scratch[3],Fp3{},a,d,f);
            else polynomial(g.op,a,d,values[g.y],Fp3{},f);
            if(!(index&half)) {
                c[0]=f[0];c[1]=sub(f[1],f[0]);c[2]=sub(f[2],f[1]);
            } else {c[1]=f[0];c[2]=f[1];}
            for(auto& value:c)value=mul6(value,g.weight);
        }
    }
    for(unsigned j=0;j<3;++j)sum[j][tid]=c[j];__syncthreads();
    for(unsigned step=threads/2;step;step/=2) {
        if(tid<step)for(unsigned j=0;j<3;++j)sum[j][tid]=add(sum[j][tid],sum[j][tid+step]);__syncthreads();
    }
    if(!tid)for(unsigned j=0;j<3;++j)scratch[6+blockIdx.x*3+j]=sum[j][0];
}
__global__ void finish(unsigned blocks,bool terminal,const Fp3* vector,Fp3* scratch) {
    __shared__ Fp3 sum[threads];
    const unsigned tid=threadIdx.x,j=blockIdx.x;Fp3 value{};
    for(unsigned i=tid;i<blocks;i+=threads)value=add(value,scratch[6+3*i+j]);
    sum[tid]=value;__syncthreads();
    for(unsigned step=threads/2;step;step/=2) {if(tid<step)sum[tid]=add(sum[tid],sum[tid+step]);__syncthreads();}
    if(!tid) {scratch[j]=sum[0];if(terminal && j==0) {scratch[4]=vector[0];scratch[5]={};}}
}
}
cudaError_t start(cudaStream_t stream,unsigned n,unsigned p,c71_rms_prefix::Gate* gates,
    const c71_rms_prefix::GateRange* ranges,const Fp3* selectors) {
    bind_selectors<<<(n+threads-1)/threads,threads,0,stream>>>(n,p,gates,ranges,selectors);return cudaGetLastError();
}
cudaError_t advance(cudaStream_t stream,unsigned n,unsigned width,unsigned half,bool right,
    const Fp3* point,c71_rms_prefix::Gate* gates,Fp3* values) {
    advance_state<<<(std::max(n,half)+threads-1)/threads,threads,0,stream>>>(n,half,right,point,gates,values+width);return cudaGetLastError();
}
cudaError_t left(cudaStream_t stream,Fp3* scratch,const Fp3* vector) {
    save_left<<<1,1,0,stream>>>(scratch,vector);return cudaGetLastError();
}
cudaError_t coefficients(cudaStream_t stream,unsigned n,unsigned width,unsigned original_width,bool right,bool terminal,
    const c71_rms_prefix::Gate* gates,const Fp3* values,Fp3* scratch) {
    gate_coefficients<<<(n+threads-1)/threads,threads,0,stream>>>(n,width,original_width,right,terminal,gates,values,scratch);return cudaGetLastError();
}
cudaError_t reduce(cudaStream_t stream,unsigned blocks,bool terminal,const Fp3* vector,Fp3* scratch) {
    finish<<<3,threads,0,stream>>>(blocks,terminal,vector,scratch);return cudaGetLastError();
}
}

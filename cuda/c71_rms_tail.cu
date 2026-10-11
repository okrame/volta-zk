#include <cuda_runtime.h>
#include "c71_rms_tail.cuh"
namespace c71_rms_tail {
using namespace c71_range;
namespace {
__device__ bool zero(Fp3 v) {return !(v.c0|v.c1|v.c2);}
__device__ Fp3 combined_eq(const Fp3* a,const Fp3* b,unsigned bits,unsigned index) {
    Fp3 result{1,0,0};
    for(unsigned i=0;i<bits;++i) {
        const bool one=(index>>(bits-1-i))&1;
        result=mul6(result,mul6(one?a[i]:sub(Fp3{1,0,0},a[i]),one?b[i]:sub(Fp3{1,0,0},b[i])));
    }
    return result;
}
__global__ void factors(Shape s,Fp3* table) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    const unsigned left=(s.round-4)/2,right=s.round-4-left,l=1u<<left,r=1u<<right;
    const auto* original=table;const auto* challenges=table+29;
    if(i<l) {
        table[point_slots+i]=equality(challenges,left,i);
        table[point_slots+2*max_half+i]=combined_eq(challenges,original,left,i);
    }
    if(i<r) {
        table[point_slots+max_half+i]=equality(challenges+left,right,i);
        table[point_slots+3*max_half+i]=combined_eq(challenges+left,original+left,right,i);
    }
}
__global__ void luts(Shape s,Fp3* table) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=512)return;
    const unsigned first=(i/256)*8,mask=i%256;
    Fp3 value{},selector{};
    for(unsigned row=0;row<8;++row)if((mask>>row)&1) {
        const auto weight=equality(table+29+s.round-4,4,first+row);
        value=add(value,weight);
        selector=add(selector,mul6(weight,equality(table+s.round-4,4,first+row)));
    }
    table[wire_lut+i]=value;table[selector_lut+i]=selector;
}
__global__ void suffix_eq(Shape s,unsigned first,Fp3* table) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=2*s.n)return;
    const unsigned side=i/s.n,k=i%s.n,half=(1u<<(s.bits-s.round))/2;
    table[suffix+i]=equality(table+s.round,s.bits-s.round,first+side*half+k);
}
__global__ void fold_rows(Shape s,unsigned side,unsigned first,unsigned groups,
    const uint64_t* stage,const uint16_t* ids,const Fp3* table,Fp3* folded) {
    const unsigned job=blockIdx.x*blockDim.x+threadIdx.x,stride=s.width+s.programs;
    if(job>=s.n*stride)return;
    const unsigned k=job/stride,wire=job%stride;
    const unsigned right=s.round-4-(s.round-4)/2,mask=(1u<<right)-1;
    Fp3 value=folded[uint64_t(side)*s.n*stride+job];
    for(unsigned g=0;g<groups;++g) {
        const unsigned group=first+g,slot=g*s.n+k;
        unsigned bits=0;
        if(wire<s.width)bits=unsigned(stage[uint64_t(wire)*(s.capacity/4)+slot/4]>>(16*(slot%4)))&65535;
        else for(unsigned row=0;row<16;++row)if(ids[row*s.capacity+slot]==wire-s.width)bits|=1u<<row;
        const unsigned base=wire<s.width?wire_lut:selector_lut;
        const unsigned factor=point_slots+(wire<s.width?0:2*max_half);
        const auto amplitude=mul6(table[factor+(group>>right)],table[factor+max_half+(group&mask)]);
        const auto partial=add(table[base+(bits&255)],table[base+256+(bits>>8)]);
        value=add(value,mul6(amplitude,partial));
    }
    folded[uint64_t(side)*s.n*stride+job]=value;
}
__global__ void finish_selectors(Shape s,const Fp3* table,Fp3* folded) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=2*s.programs)return;
    const unsigned side=i/s.programs,p=i%s.programs;
    auto& value=folded[uint64_t(side)*(s.width+s.programs)+s.width+p];
    value=mul6(value,table[suffix+side]);
}
__global__ void all_program_values(Shape s,const c71_rms_prefix::Gate* gates,
    const c71_rms_prefix::GateRange* ranges,const Fp3* table,const Fp3* folded,Fp3* values) {
    const unsigned program=blockIdx.x/s.n,k=blockIdx.x%s.n,thread=threadIdx.x;
    const unsigned stride=s.width+s.programs;
    const auto* lo=folded+uint64_t(k)*stride;const auto* hi=lo+uint64_t(s.n)*stride;
    auto* output=values+uint64_t(program*s.n+k)*4;
    if(zero(lo[s.width+program]) && zero(hi[s.width+program])) {
        if(!thread)for(unsigned c=0;c<4;++c)output[c]={};
        return;
    }
    Fp3 u[3]{};const auto range=ranges[program];
    for(unsigned i=thread;i<range.count;i+=128) {
        const auto g=gates[range.first+i];const auto x=lo[g.x],dx=sub(hi[g.x],x);
        Fp3 v[3]{};
        if(g.op==2) {v[0]=x;v[1]=dx;}
        else {
            const auto y=lo[g.y],dy=sub(hi[g.y],y);
            v[0]=mul6(x,y);v[1]=add(mul6(x,dy),mul6(dx,y));v[2]=mul6(dx,dy);
            if(g.op==1) {v[0]=sub(add(x,y),add(v[0],v[0]));
                v[1]=sub(add(dx,dy),add(v[1],v[1]));v[2]=sub(Fp3{},add(v[2],v[2]));}
        }
        for(unsigned c=0;c<3;++c)u[c]=add(u[c],mul6(v[c],g.weight));
    }
    __shared__ Fp3 partial[3][128];
    for(unsigned c=0;c<3;++c)partial[c][thread]=u[c];__syncthreads();
    for(unsigned step=64;step;step/=2) {
        if(thread<step)for(unsigned c=0;c<3;++c)partial[c][thread]=add(partial[c][thread],partial[c][thread+step]);
        __syncthreads();
    }
    if(!thread) {
        const auto a=mul6(lo[s.width+program],table[suffix+k]);
        const auto b=sub(mul6(hi[s.width+program],table[suffix+s.n+k]),a);
        for(unsigned c=0;c<4;++c) {
            Fp3 value{};
            if(c<3)value=mul6(a,partial[c][0]);
            if(c)value=add(value,mul6(b,partial[c-1][0]));
            output[c]=value;
        }
    }
}
__global__ void all_program_sum(Shape s,const Fp3* values,Fp3* coefficients) {
    __shared__ Fp3 partial[256];const unsigned thread=threadIdx.x,c=blockIdx.x;
    Fp3 value{};
    for(unsigned i=thread;i<s.programs*s.n;i+=256)value=add(value,values[uint64_t(i)*4+c]);
    partial[thread]=value;__syncthreads();
    for(unsigned step=128;step;step/=2) {
        if(thread<step)partial[thread]=add(partial[thread],partial[thread+step]);__syncthreads();
    }
    if(!thread)coefficients[c]=add(coefficients[c],partial[0]);
}
}
cudaError_t prepare(cudaStream_t stream,Shape s,Fp3* table,unsigned* attempted) {
    *attempted=1;
    const unsigned half=1u<<((s.round-4+1)/2);
    factors<<<(half+127)/128,128,0,stream>>>(s,table);
    auto status=cudaGetLastError();if(status!=cudaSuccess)return status;
    ++*attempted;
    luts<<<4,128,0,stream>>>(s,table);return cudaGetLastError();
}
cudaError_t suffix_weights(cudaStream_t stream,Shape s,unsigned first,Fp3* table) {
    suffix_eq<<<(2*s.n+127)/128,128,0,stream>>>(s,first,table);return cudaGetLastError();
}
cudaError_t fold(cudaStream_t stream,Shape s,unsigned side,unsigned first,unsigned groups,
    const uint64_t* stage,const uint16_t* ids,const Fp3* table,Fp3* folded) {
    fold_rows<<<(uint64_t(s.n)*(s.width+s.programs)+127)/128,128,0,stream>>>(s,side,first,groups,stage,ids,table,folded);
    return cudaGetLastError();
}
cudaError_t terminal_selectors(cudaStream_t stream,Shape s,const Fp3* table,Fp3* folded) {
    finish_selectors<<<(2*s.programs+127)/128,128,0,stream>>>(s,table,folded);return cudaGetLastError();
}
cudaError_t program_values(cudaStream_t stream,Shape s,const c71_rms_prefix::Gate* gates,
    const c71_rms_prefix::GateRange* ranges,const Fp3* table,const Fp3* folded,Fp3* values) {
    all_program_values<<<s.programs*s.n,128,0,stream>>>(s,gates,ranges,table,folded,values);
    return cudaGetLastError();
}
cudaError_t sum_programs(cudaStream_t stream,Shape s,const Fp3* values,Fp3* coefficients) {
    all_program_sum<<<4,256,0,stream>>>(s,values,coefficients);return cudaGetLastError();
}
}

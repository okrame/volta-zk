// Same natural finite FFT and stream as the commitment; one output column.
#include <cuda_runtime.h>
#include <algorithm>
#include <cmath>
#include <vector>
#include "c71_pcs_query.cuh"
#include "c71_fft.cuh"
namespace {
__device__ uint64_t high_at(const uint64_t* high,uint64_t task,uint64_t degree,uint64_t j,bool children) {
    return children ? high[(task/2)*2*degree+degree+j] : high[j];
}
__device__ uint64_t low_at(const uint64_t* low,uint64_t task,uint64_t degree,uint64_t j,bool children) {
    return children ? low[(task/2)*2*degree+j] : low[j];
}
__global__ void load_low(const uint8_t* bytes,const uint64_t* pads,uint64_t* low,
    uint64_t count,c71_pcs::QueryBlock s) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count) return;
    const uint64_t j=s.first+i;
    uint64_t value=0;
    if(j<s.source_rows) {
        if(s.pad_only) value=pads[s.pad_first+j];
        else if(j<s.active) value=bytes[s.byte_first+j-s.window_first];
        else if(j>=s.message_rows) value=pads[s.pad_first+j-s.message_rows];
    }
    low[i]=value;
}
__global__ void load_weight_low(const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,uint64_t* low,
    uint64_t count,c71_pcs::QueryBlock shape) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) low[i]=c71_pcs::query_weight_low_at(weights,tiles,tile_count,live,pads,shape,shape.first+i);
}
__global__ void tiny_remainders(const uint64_t* high,const uint64_t* low,const uint64_t* spectrum,
    uint64_t* output,uint64_t degree,uint64_t batch,bool children) {
    const uint64_t task=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(task>=batch) return;
    const uint64_t* factor=spectrum+task*2*degree;
    if(degree==1) {
        output[task]=fp_add(low_at(low,task,1,0,children),
            fp_mul(high_at(high,task,1,0,children),fp_sub(1,factor[0])));
        return;
    }
    if(degree==2) {
        constexpr uint64_t half=0x7fffffff80000001ULL;
        const uint64_t m0=fp_sub(fp_mul(fp_add(factor[0],factor[2]),half),1);
        const uint64_t m1=fp_mul(fp_sub(factor[0],factor[2]),half);
        const uint64_t h0=high_at(high,task,2,0,children),h1=high_at(high,task,2,1,children);
        const uint64_t q0=fp_sub(h0,fp_mul(h1,m1));
        output[2*task]=fp_sub(low_at(low,task,2,0,children),fp_mul(q0,m0));
        output[2*task+1]=fp_sub(fp_sub(low_at(low,task,2,1,children),fp_mul(h1,m0)),fp_mul(q0,m1));
        return;
    }
    uint64_t hi[8],lo[8],modulus[8];
    const uint64_t root=c71_pcs::power(c71_pcs::power(7,(P-1)/(2*degree)),P-2);
    const uint64_t scale=c71_pcs::power(2*degree,P-2);
    for(uint64_t j=0;j<degree;++j) {
        hi[j]=high_at(high,task,degree,j,children);
        lo[j]=low_at(low,task,degree,j,children);
        const uint64_t step=c71_pcs::power(root,j);
        uint64_t w=1,sum=0;
        for(uint64_t k=0;k<2*degree;++k) { sum=fp_add(sum,fp_mul(factor[k],w)); w=fp_mul(w,step); }
        modulus[j]=fp_mul(sum,scale);
    }
    for(int j=int(degree)-1;j>=0;--j) {
        const uint64_t quotient=hi[j];
        for(uint64_t k=0;k<degree;++k) {
            const uint64_t index=uint64_t(j)+k,value=fp_mul(quotient,modulus[k]);
            if(index<degree) lo[index]=fp_sub(lo[index],value);
            else hi[index-degree]=fp_sub(hi[index-degree],value);
        }
    }
    for(uint64_t j=0;j<degree;++j) output[task*degree+j]=lo[j];
}
__global__ void reverse_high(const uint64_t* high,uint64_t* work,uint64_t degree,uint64_t count,bool children) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count) return;
    const uint64_t local=i%(2*degree),task=i/(2*degree);
    work[i]=local<degree ? high_at(high,task,degree,degree-1-local,children) : 0;
}
__global__ void multiply_factor(uint64_t* work,const uint64_t* factor,uint64_t count) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) work[i]=fp_mul(work[i],factor[i]); // distinct spectrum for every child
}
__global__ void reverse_quotient(const uint64_t* work,uint64_t* quotient,uint64_t degree,uint64_t count) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count) return;
    const uint64_t local=i%(2*degree),base=i-local;
    quotient[i]=local<degree ? work[base+degree-1-local] : 0;
}
__global__ void subtract_product(const uint64_t* low,const uint64_t* product,uint64_t* output,
    uint64_t degree,uint64_t count,bool children) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) output[i]=fp_sub(low_at(low,i/degree,degree,i%degree,children),
        product[(i/degree)*2*degree+i%degree]);
}
__global__ void extend_shift(const uint64_t* input,uint64_t* work,uint64_t degree) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<2*degree) work[i]=i<degree ? input[i] : 0;
}
__global__ void split_product(const uint64_t* product,uint64_t* low,uint64_t* high,uint64_t degree) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<degree) { low[i]=product[i]; high[i]=product[degree+i]; }
}
__global__ void add_correction(uint64_t* output,const uint64_t* correction,uint64_t count) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) output[i]=fp_add(output[i],correction[i]);
}
cudaError_t transform(cudaStream_t stream,uint64_t* values,uint64_t* scratch,const uint64_t* twiddles,
    unsigned log,unsigned batch,bool inverse,unsigned* attempted,uint64_t* copied) {
    const unsigned before=*attempted;
    const auto status=c71_fft::launch_natural(stream,values,scratch,twiddles,log,batch,inverse,attempted);
    if(log%2 && log>1 && *attempted-before>1) *copied+=(uint64_t{1}<<log)*batch*8;
    return status;
}
}
extern "C" cudaError_t c71_pcs_query_low_launch(cudaStream_t stream,const uint8_t* bytes,const uint64_t* pads,
    uint64_t* output,uint64_t count,c71_pcs::QueryBlock shape) {
    if(!stream || !pads || !output || !count || count>(uint64_t{1}<<20) ||
       (!shape.pad_only && shape.first<shape.active && !bytes)) return cudaErrorInvalidValue;
    load_low<<<unsigned((count+255)/256),256,0,stream>>>(bytes,pads,output,count,shape);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_query_weight_low_launch(cudaStream_t stream,const int16_t* weights,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t live,const uint64_t* pads,
    uint64_t pad_count,uint64_t* output,uint64_t capacity,c71_pcs::QueryBlock shape) {
    if(!stream || !weights || !tiles || !tile_count || tile_count>65536 || !pads || !output ||
       static_cast<const void*>(weights)==static_cast<const void*>(output) ||
       static_cast<const void*>(tiles)==static_cast<const void*>(output) || pads==output ||
       !c71_pcs::valid_query_weight_low(shape,capacity,live,pad_count)) return cudaErrorInvalidValue;
    load_weight_low<<<unsigned((capacity+255)/256),256,0,stream>>>(weights,tiles,tile_count,live,pads,output,capacity,shape);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_query_remainder_launch(cudaStream_t stream,const uint64_t* high,const uint64_t* low,
    const uint64_t* inverse,const uint64_t* modulus,const uint64_t* forward,const uint64_t* backward,
    uint64_t* work,uint64_t* scratch,uint64_t* output,uint64_t degree,uint64_t count,unsigned children,
    unsigned* attempted,uint64_t* copied) {
    if(!stream || !high || !low || !inverse || !modulus || !forward || !backward || !work || !scratch || !output ||
       !attempted || !copied || !count || count>(uint64_t{1}<<20) || !degree || (degree&(degree-1)) ||
       degree>count || count%degree || children>1 || work==scratch || work==output || scratch==output ||
       high==output || low==output) return cudaErrorInvalidValue;
    const unsigned batch=unsigned(count/degree),grid=unsigned((2*count+255)/256);
    if(degree<=8) {
        ++*attempted;
        tiny_remainders<<<unsigned((batch+127)/128),128,0,stream>>>(high,low,modulus,output,degree,batch,children!=0);
        return cudaGetLastError();
    }
    unsigned log=0; while((uint64_t{1}<<log)<2*degree) ++log;
    ++*attempted;
    reverse_high<<<grid,256,0,stream>>>(high,work,degree,2*count,children!=0);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,work,scratch,forward,log,batch,false,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    multiply_factor<<<grid,256,0,stream>>>(work,inverse,2*count);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,work,scratch,backward,log,batch,true,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    reverse_quotient<<<grid,256,0,stream>>>(work,scratch,degree,2*count);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,scratch,work,forward,log,batch,false,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    multiply_factor<<<grid,256,0,stream>>>(scratch,modulus,2*count);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,scratch,work,backward,log,batch,true,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    subtract_product<<<unsigned((count+255)/256),256,0,stream>>>(low,scratch,output,degree,count,children!=0);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_query_shift_launch(cudaStream_t stream,const uint64_t* values,const uint64_t* shift,
    const uint64_t* forward,const uint64_t* backward,uint64_t* work,uint64_t* scratch,uint64_t* low,uint64_t* high,
    uint64_t degree,unsigned* attempted,uint64_t* copied) {
    if(!stream || !values || !shift || !forward || !backward || !work || !scratch || !low || !high ||
       !attempted || !copied || !degree || degree>(uint64_t{1}<<20) || (degree&(degree-1)) ||
       work==scratch || low==high || work==low || work==high || scratch==low || scratch==high)
        return cudaErrorInvalidValue;
    const unsigned grid=unsigned((2*degree+255)/256);
    unsigned log=0; while((uint64_t{1}<<log)<2*degree) ++log;
    ++*attempted;
    extend_shift<<<grid,256,0,stream>>>(values,work,degree);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,work,scratch,forward,log,1,false,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    multiply_factor<<<grid,256,0,stream>>>(work,shift,2*degree);
    if(const auto e=cudaGetLastError();e!=cudaSuccess) return e;
    if(const auto e=transform(stream,work,scratch,backward,log,1,true,attempted,copied);e!=cudaSuccess) return e;
    ++*attempted;
    split_product<<<unsigned((degree+255)/256),256,0,stream>>>(work,low,high,degree);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_query_add_launch(cudaStream_t stream,uint64_t* values,const uint64_t* correction,uint64_t count) {
    if(!stream || !values || !correction || values==correction || !count || count>(uint64_t{1}<<20)) return cudaErrorInvalidValue;
    add_correction<<<unsigned((count+255)/256),256,0,stream>>>(values,correction,count);
    return cudaGetLastError();
}

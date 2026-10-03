#include <cuda_runtime.h>
#include "c71_dense_i16.cuh"
#include "c71_byte_gather.cuh"
#include "c71_nonlinear.cuh"
using namespace c71_dense;

__device__ __forceinline__ void mma(int32_t (&d)[4],const uint32_t (&a)[4],const uint32_t (&b)[2]) {
    // No saturation or floating-point intermediate. Checked K bounds every
    // prefix of each accumulator, not merely the recomposed final result.
    asm volatile("mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
        : "+r"(d[0]),"+r"(d[1]),"+r"(d[2]),"+r"(d[3])
        : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
}
// 4 independent warps per CTA, output tile 16x32. Original X[M,K] and
// W[N,K] are row-major: W is already the MMA column-major right operand.
// ponytail: direct fragment loads, no extra W packing/cache; only add shared
// tiling after authorized profiling shows that repeated loads are material.
extern "C" __global__ void c71_dense_i16_mma(const int16_t* x,const int16_t* w,
    int64_t* out,uint32_t* failed,Shape s) {
    const unsigned lane=threadIdx.x%32, row0=blockIdx.y*16, col0=blockIdx.x*32+(threadIdx.x/32)*8;
    if(col0>=s.n) return; // Uniform within the entire warp, never a partial MMA.
    int32_t hh[4]{},hl[4]{},lh[4]{},ll[4]{},sx[2]{},sw=0;
    bool invalid=false;
    for(unsigned first=0;first<s.k;first+=32) {
        uint32_t ah[4]{},al[4]{},bh[2]{},bl[2]{};
#pragma unroll
        for(unsigned r=0;r<4;++r) {
#pragma unroll
            for(unsigned b=0;b<4;++b) {
                const unsigned row=row0+a_row(lane,r),k=first+a_k(lane,r,b);
                const int16_t v=row<s.m && k<s.k ? x[size_t(row)*s.k+k]:0;
                invalid|=v==INT16_MIN; sx[r%2]+=v; pack(v,b,ah[r],al[r]);
            }
        }
#pragma unroll
        for(unsigned r=0;r<2;++r) {
#pragma unroll
            for(unsigned b=0;b<4;++b) {
                const unsigned row=col0+w_row(lane),k=first+w_k(lane,r,b);
                const int16_t v=row<s.n && k<s.k ? w[size_t(row)*s.k+k]:0;
                invalid|=v==INT16_MIN; sw+=v; pack(v,b,bh[r],bl[r]);
            }
        }
        mma(hh,ah,bh); mma(hl,ah,bl); mma(lh,al,bh); mma(ll,al,bl);
    }
    const bool bad=__any_sync(0xffffffffu,invalid);
    if(bad && lane==0) atomicOr(failed,1u);
    // Four adjacent lanes partition K for each A row / W column. Integer
    // sums remain bounded by K*32768, safely below signed int32.
#pragma unroll
    for(unsigned shift=1;shift<=2;shift*=2) {
        sx[0]+=__shfl_xor_sync(0xffffffffu,sx[0],shift);
        sx[1]+=__shfl_xor_sync(0xffffffffu,sx[1],shift);
        sw+=__shfl_xor_sync(0xffffffffu,sw,shift);
    }
#pragma unroll
    for(unsigned r=0;r<4;++r) {
        const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
        const int32_t sum_w=__shfl_sync(0xffffffffu,sw,4*out_col(lane,r));
        const int64_t value=compose(hh[r],hl[r],lh[r],ll[r],sx[r/2],sum_w,(s.k+31)&~31u);
        if(row<s.m && col<s.n) out[size_t(row)*s.n+col]=value;
    }
}

// Internal pointer launcher, no allocator, reset, fence or CPU fallback. The
// resident caller must own capacities, initialize a sticky zero error flag,
// then fence/check it BEFORE using any result, including in another kernel.
extern "C" cudaError_t c71_dense_i16_launch(cudaStream_t stream,const int16_t* x,uint64_t x_words,
    const int16_t* w,uint64_t w_words,int64_t* out,uint64_t out_values,uint32_t* failed,Shape s) {
    if(!stream || !valid_buffers(x,x_words,w,w_words,out,out_values,failed,s)) return cudaErrorInvalidValue;
    c71_dense_i16_mma<<<dim3((s.n+31)/32,(s.m+15)/16),128,0,stream>>>(x,w,out,failed,s);
    return cudaGetLastError();
}

extern "C" __global__ void c71_dense_rne(const int64_t* raw,int16_t* output,uint64_t count,
                                        int32_t shift,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) {
        int16_t y=0;
        if(!quantize(raw[i],shift,y)) atomicOr(failed,1u);
        else output[i]=y;
    }
}
extern "C" cudaError_t c71_dense_rne_launch(cudaStream_t stream,const int64_t* raw,int16_t* output,
    uint64_t count,int32_t shift,uint32_t* failed) {
    uintptr_t re,oe,fe;
    if(!stream || !count || count>uint64_t(max_m)*max_n ||
       reinterpret_cast<uintptr_t>(raw)%8 || reinterpret_cast<uintptr_t>(output)%2 ||
       reinterpret_cast<uintptr_t>(failed)%4 || !span(raw,count*8,re) ||
       !span(output,count*2,oe) || !span(failed,4,fe) || overlaps(raw,re,output,oe) ||
       overlaps(raw,re,failed,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    c71_dense_rne<<<(count+255)/256,256,0,stream>>>(raw,output,count,shift,failed);
    return cudaGetLastError();
}

extern "C" __global__ void c71_dense_pointwise_kernel(const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,Pointwise op,uint32_t* failed) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) {
        const int16_t a=(op.multiply || op.a)?x[i]:0, b=(op.multiply || op.b)?y[i]:0;
        int64_t value=0;
        if(!pointwise(a,b,op,value)) atomicOr(failed,1u);
        else output[i]=value;
    }
}
extern "C" cudaError_t c71_dense_pointwise_launch(cudaStream_t stream,const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,Pointwise op,uint32_t* failed) {
    uintptr_t oe,fe;
    if(!stream || !valid_pointwise(op) || !count || count>uint64_t(max_m)*max_n ||
       reinterpret_cast<uintptr_t>(output)%8 || reinterpret_cast<uintptr_t>(failed)%4 ||
       !span(output,count*8,oe) || !span(failed,4,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    const int16_t* inputs[]={x,y}; const bool used[]={op.multiply || op.a,op.multiply || op.b};
    for(unsigned j=0;j<2;++j) {
        uintptr_t end;
        if(used[j] ? (reinterpret_cast<uintptr_t>(inputs[j])%2 || !span(inputs[j],count*2,end) ||
           overlaps(inputs[j],end,output,oe) || overlaps(inputs[j],end,failed,fe)) : inputs[j]!=nullptr) return cudaErrorInvalidValue;
    }
    c71_dense_pointwise_kernel<<<(count+255)/256,256,0,stream>>>(x,y,output,count,op,failed);
    return cudaGetLastError();
}

extern "C" __global__ void c71_byte_scatter_kernel(const void* input,unsigned kind,
    uint8_t* output,uint32_t* failed,c71_byte::Tile t) {
    const uint64_t count=t.rows*t.columns*t.width;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const uint64_t address=c71_byte::ordered(t.original_first+i,t);
        if(address<t.window_first || address-t.window_first>=t.window_length) continue;
        const uint64_t word=i/t.width, index=t.input_first+(word/t.columns)*t.input_stride+word%t.columns;
        const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
        uint8_t byte=0;
        if(!c71_byte::encode(value,t.signed_width,t.byte_first+i%t.width,byte)) atomicOr(failed,1u);
        else output[address-t.window_first]=byte;
    }
}

extern "C" __global__ void c71_rms_kernel(const int16_t* input,const int16_t* weights,
    int64_t* products,int64_t* statistics,int16_t* output,c71_nonlinear::Rms shape,uint32_t* failed) {
    __shared__ uint64_t sums[256];
    const uint64_t first=uint64_t(blockIdx.x)*shape.columns;
    uint64_t sum=0;
    for(unsigned column=threadIdx.x;column<shape.columns;column+=256) {
        const int64_t value=input[first+column];
        if(value==INT16_MIN) atomicOr(failed,1u);
        sum+=value*value;
    }
    sums[threadIdx.x]=sum; __syncthreads();
    for(unsigned stride=128;stride;stride/=2) {
        if(threadIdx.x<stride) sums[threadIdx.x]+=sums[threadIdx.x+stride];
        __syncthreads();
    }
    if(!threadIdx.x) statistics[blockIdx.x]=sums[0];
    for(unsigned column=threadIdx.x;column<shape.columns;column+=256) {
        const int16_t weight=shape.weighted?weights[column]:1;
        const int64_t product=int64_t(input[first+column])*weight;
        int16_t rounded;
        if(weight==INT16_MIN || !c71_nonlinear::rms_round(shape,product,sums[0],rounded)) atomicOr(failed,1u);
        else output[first+column]=rounded;
        if(shape.weighted) products[first+column]=product;
    }
}
extern "C" cudaError_t c71_rms_launch(cudaStream_t stream,const int16_t* input,const int16_t* weights,
    int64_t* products,int64_t* statistics,int16_t* output,c71_nonlinear::Rms shape,uint32_t* failed) {
    if(!stream || !input || !statistics || !output || !failed || !c71_nonlinear::valid(shape) ||
        (shape.weighted && (!weights || !products))) return cudaErrorInvalidValue;
    c71_rms_kernel<<<shape.rows*shape.heads,256,0,stream>>>(input,weights,products,statistics,output,shape,failed);
    return cudaGetLastError();
}
extern "C" __global__ void c71_qk_kernel(const int16_t* query,const int16_t* keys,int64_t* output,
    c71_nonlinear::Attention shape,uint32_t* failed) {
    const unsigned columns=shape.old+150,group=shape.head/(32/shape.groups);
    const uint64_t count=uint64_t(shape.rows)*columns;
    for(uint64_t index=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;index<count;index+=uint64_t(gridDim.x)*blockDim.x) {
        const unsigned row=index/columns,key=index%columns;
        int64_t sum=0;
        if(key<=shape.old+shape.first+row) for(unsigned lane=0;lane<shape.lanes;++lane) {
            const int16_t left=query[(uint64_t(row)*32+shape.head)*shape.lanes+lane];
            const int16_t right=keys[(uint64_t(key)*shape.groups+group)*shape.lanes+lane];
            if(left==INT16_MIN || right==INT16_MIN) atomicOr(failed,1u);
            sum+=int64_t(left)*right;
        }
        output[index]=sum;
    }
}
extern "C" cudaError_t c71_qk_launch(cudaStream_t stream,const int16_t* query,const int16_t* keys,
    int64_t* output,c71_nonlinear::Attention shape,uint32_t* failed) {
    if(!stream || !query || !keys || !output || !failed || !c71_nonlinear::valid(shape)) return cudaErrorInvalidValue;
    c71_qk_kernel<<<(uint64_t(shape.rows)*(shape.old+150)+255)/256,256,0,stream>>>(query,keys,output,shape,failed);
    return cudaGetLastError();
}
struct C71PiPointers { const int16_t* heads[32]; };
extern "C" __global__ void c71_pv_kernel(C71PiPointers probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention shape,uint32_t* failed) {
    const unsigned columns=shape.old+150;
    const uint64_t count=uint64_t(shape.rows)*32*shape.lanes;
    for(uint64_t index=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;index<count;index+=uint64_t(gridDim.x)*blockDim.x) {
        const unsigned lane=index%shape.lanes,head=index/shape.lanes%32,row=index/(32*shape.lanes),group=head/(32/shape.groups);
        int64_t sum=0;
        for(unsigned key=0;key<=shape.old+shape.first+row;++key) {
            const int16_t probability=probabilities.heads[head][uint64_t(row)*columns+key];
            const int16_t value=values[(uint64_t(key)*shape.groups+group)*shape.lanes+lane];
            if(probability<0 || probability>16384 || value==INT16_MIN) atomicOr(failed,1u);
            sum+=int64_t(probability)*value;
        }
        output[index]=sum;
    }
}
extern "C" cudaError_t c71_pv_launch(cudaStream_t stream,const int16_t* const* probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention shape,uint32_t* failed) {
    if(!stream || !probabilities || !values || !output || !failed || !c71_nonlinear::valid(shape)) return cudaErrorInvalidValue;
    C71PiPointers pointers{};
    for(unsigned head=0;head<32;++head) {
        if(!probabilities[head]) return cudaErrorInvalidValue;
        pointers.heads[head]=probabilities[head];
    }
    c71_pv_kernel<<<(uint64_t(shape.rows)*32*shape.lanes+255)/256,256,0,stream>>>(pointers,values,output,shape,failed);
    return cudaGetLastError();
}
extern "C" __global__ void c71_softmax_kernel(const int16_t* scores,const int32_t* table,
    int16_t* maximum,int16_t* difference,int64_t* exponential,int64_t* denominator,int16_t* probabilities,
    unsigned long long* histogram,c71_nonlinear::Attention shape,uint32_t* failed) {
    __shared__ int maxima[256];
    __shared__ int64_t sums[256];
    const unsigned columns=shape.old+150,live=shape.old+shape.first+blockIdx.x+1;
    const uint64_t first=uint64_t(blockIdx.x)*columns;
    int largest=INT16_MIN;
    for(unsigned column=threadIdx.x;column<columns;column+=256) {
        const int score=scores[first+column];
        if(score==INT16_MIN || (column>=live && score!=0)) atomicOr(failed,1u);
        if(column<live && score>largest) largest=score;
    }
    maxima[threadIdx.x]=largest; __syncthreads();
    for(unsigned stride=128;stride;stride/=2) {
        if(threadIdx.x<stride && maxima[threadIdx.x+stride]>maxima[threadIdx.x]) maxima[threadIdx.x]=maxima[threadIdx.x+stride];
        __syncthreads();
    }
    if(!threadIdx.x) maximum[blockIdx.x]=maxima[0];
    int64_t sum=0;
    for(unsigned column=threadIdx.x;column<columns;column+=256) {
        const int delta=column<live?maxima[0]-scores[first+column]:0;
        exponential[first+column]=0;
        if(delta<0 || delta>65534) { atomicOr(failed,1u); continue; }
        const int32_t value=table[delta];
        if(value<0 || value>(1<<30) || (delta==0 && value!=(1<<30))) { atomicOr(failed,1u); continue; }
        difference[first+column]=int16_t(delta-32767); exponential[first+column]=value;
        atomicAdd(histogram+delta,1ULL);
        if(column<live) sum+=value;
    }
    sums[threadIdx.x]=sum; __syncthreads();
    for(unsigned stride=128;stride;stride/=2) {
        if(threadIdx.x<stride) sums[threadIdx.x]+=sums[threadIdx.x+stride];
        __syncthreads();
    }
    const int64_t total=sums[0];
    if(!threadIdx.x) denominator[blockIdx.x]=total;
    if(total<(int64_t{1}<<30) || total>int64_t(live)*(1<<30)) { atomicOr(failed,1u); return; }
    for(unsigned column=threadIdx.x;column<columns;column+=256)
        probabilities[first+column]=column<live?c71_nonlinear::probability(int32_t(exponential[first+column]),total):0;
}
extern "C" cudaError_t c71_softmax_launch(cudaStream_t stream,const int16_t* scores,const int32_t* table,
    int16_t* maximum,int16_t* difference,int64_t* exponential,int64_t* denominator,int16_t* probabilities,
    int64_t* histogram,c71_nonlinear::Attention shape,uint32_t* failed) {
    if(!stream || !scores || !table || !maximum || !difference || !exponential || !denominator || !probabilities || !histogram || !failed ||
       !c71_nonlinear::valid(shape)) return cudaErrorInvalidValue;
    c71_softmax_kernel<<<shape.rows,256,0,stream>>>(scores,table,maximum,difference,exponential,denominator,probabilities,
        reinterpret_cast<unsigned long long*>(histogram),shape,failed);
    return cudaGetLastError();
}

extern "C" __global__ void c71_lookup_kernel(const int16_t* input,const int16_t* table,
    int16_t* output,unsigned long long* histogram,uint64_t count,uint32_t* failed) {
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        int16_t y; uint32_t entry;
        if(!c71_nonlinear::lookup(input[i],table,y,entry)) atomicOr(failed,1u);
        else { output[i]=y; atomicAdd(histogram+entry,1ULL); }
    }
}
extern "C" cudaError_t c71_lookup_launch(cudaStream_t stream,const int16_t* input,const int16_t* table,
    int16_t* output,int64_t* histogram,uint64_t count,uint32_t* failed) {
    if(!stream || !input || !table || !output || !histogram || !failed || !count || count>uint64_t(max_m)*max_n) return cudaErrorInvalidValue;
    c71_lookup_kernel<<<(count+255)/256>65535?65535:(count+255)/256,256,0,stream>>>(input,table,output,reinterpret_cast<unsigned long long*>(histogram),count,failed);
    return cudaGetLastError();
}
extern "C" __global__ void c71_histogram_seal_kernel(int64_t* histogram,uint32_t* failed) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i<65535) {
        const int64_t n=histogram[i];
        if(n<0 || n>INT32_MAX) atomicOr(failed,1u);
    }
}
extern "C" cudaError_t c71_histogram_seal_launch(cudaStream_t stream,int64_t* histogram,uint32_t* failed) {
    if(!stream || !histogram || !failed) return cudaErrorInvalidValue;
    c71_histogram_seal_kernel<<<256,256,0,stream>>>(histogram,failed); return cudaGetLastError();
}
extern "C" __global__ void c71_rope_kernel(const int16_t* input,const int32_t* coefficients,
    int64_t* output,c71_nonlinear::Rope s,uint32_t* failed) {
    const uint64_t count=uint64_t(s.rows)*s.heads*s.width/2;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const unsigned half=s.width/2,j=i%half,row=i/(s.heads*half);
        const uint64_t first=(i/half)*s.width+j,second=first+half;
        const int32_t c=j<s.pairs?coefficients[(row*s.pairs+j)*2]:1<<30;
        const int32_t sin=j<s.pairs?coefficients[(row*s.pairs+j)*2+1]:0;
        int64_t a,b;
        if(!c71_nonlinear::rotate(input[first],input[second],c,sin,a,b)) atomicOr(failed,1u);
        else { output[first]=a; output[second]=b; }
    }
}
extern "C" cudaError_t c71_rope_launch(cudaStream_t stream,const int16_t* input,const int32_t* coefficients,
    int64_t* output,c71_nonlinear::Rope s,uint32_t* failed) {
    if(!stream || !input || !coefficients || !output || !failed || !c71_nonlinear::valid(s)) return cudaErrorInvalidValue;
    const uint64_t count=uint64_t(s.rows)*s.heads*s.width/2;
    c71_rope_kernel<<<(count+255)/256,256,0,stream>>>(input,coefficients,output,s,failed); return cudaGetLastError();
}
extern "C" __global__ void c71_argmax_kernel(const int16_t* input,uint32_t* tokens,
    unsigned columns,uint32_t* failed) {
    __shared__ int maxima[256]; __shared__ unsigned indices[256];
    const auto* row=input+uint64_t(blockIdx.x)*columns;
    int maximum=INT16_MIN; unsigned best=UINT32_MAX;
    for(unsigned j=threadIdx.x;j<columns;j+=blockDim.x) {
        const int value=row[j];
        if(value==INT16_MIN) atomicOr(failed,1u);
        if(value>maximum || (value==maximum && j<best)) { maximum=value; best=j; }
    }
    maxima[threadIdx.x]=maximum; indices[threadIdx.x]=best; __syncthreads();
    for(unsigned stride=128;stride;stride/=2) {
        if(threadIdx.x<stride) {
            const unsigned other=threadIdx.x+stride;
            if(maxima[other]>maxima[threadIdx.x] || (maxima[other]==maxima[threadIdx.x] && indices[other]<indices[threadIdx.x])) {
                maxima[threadIdx.x]=maxima[other]; indices[threadIdx.x]=indices[other];
            }
        }
        __syncthreads();
    }
    if(!threadIdx.x) tokens[blockIdx.x]=indices[0];
}
extern "C" __global__ void c71_argmax_slack_kernel(const int16_t* input,const uint32_t* tokens,
    int16_t* output,unsigned rows,unsigned columns,uint32_t* failed) {
    const uint64_t count=uint64_t(rows)*columns;
    for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=uint64_t(gridDim.x)*blockDim.x) {
        const unsigned row=i/columns,j=i%columns,best=tokens[row]; int16_t value;
        if(best>=columns || !c71_nonlinear::slack(input[uint64_t(row)*columns+best],input[i],j,best,value)) atomicOr(failed,1u);
        else output[i]=value;
    }
}
extern "C" cudaError_t c71_argmax_select_launch(cudaStream_t stream,const int16_t* input,uint32_t* tokens,
    unsigned rows,unsigned columns,uint32_t* failed) {
    if(!stream || !input || !tokens || !failed || !rows || rows>150 || !columns || columns>262144) return cudaErrorInvalidValue;
    c71_argmax_kernel<<<rows,256,0,stream>>>(input,tokens,columns,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_argmax_slack_launch(cudaStream_t stream,const int16_t* input,const uint32_t* tokens,
    int16_t* output,unsigned rows,unsigned columns,uint32_t* failed) {
    if(!stream || !input || !tokens || !output || !failed || !rows || rows>150 || !columns || columns>262144) return cudaErrorInvalidValue;
    const uint64_t blocks=(uint64_t(rows)*columns+255)/256;
    c71_argmax_slack_kernel<<<blocks>65535?65535:blocks,256,0,stream>>>(input,tokens,output,rows,columns,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_byte_scatter_launch(cudaStream_t stream,const void* input,unsigned kind,
    uint64_t input_count,uint8_t* output,uint64_t output_count,uint32_t* failed,c71_byte::Tile t) {
    uintptr_t ie,oe,fe;
    if(!stream || !c71_byte::valid(t,kind,input_count,output_count) ||
       reinterpret_cast<uintptr_t>(input)%(kind==1?2:8) || reinterpret_cast<uintptr_t>(failed)%4 ||
       input_count>UINT64_MAX/(kind==1?2:8) ||
       !span(input,input_count*(kind==1?2:8),ie) || !span(output,output_count,oe) || !span(failed,4,fe) ||
       overlaps(input,ie,output,oe) || overlaps(input,ie,failed,fe) || overlaps(output,oe,failed,fe)) return cudaErrorInvalidValue;
    const uint64_t blocks=(t.rows*t.columns*t.width+255)/256;
    c71_byte_scatter_kernel<<<blocks>65535?65535:blocks,256,0,stream>>>(input,kind,output,failed,t);
    return cudaGetLastError();
}

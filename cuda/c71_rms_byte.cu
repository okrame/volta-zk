#include <cuda_runtime.h>
#include "c71_rms_byte.cuh"

namespace c71_rms_byte {
namespace {
using namespace c71_range;
using c71_rms_prefix::SourceNorm;
using c71_rms_prefix::SourceTile;
__device__ Fp3 shuffled(Fp3 v,unsigned delta) {
    return {__shfl_down_sync(0xffffffffu,static_cast<unsigned long long>(v.c0),delta),
        __shfl_down_sync(0xffffffffu,static_cast<unsigned long long>(v.c1),delta),
        __shfl_down_sync(0xffffffffu,static_cast<unsigned long long>(v.c2),delta)};
}
__device__ uint8_t source_byte(const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned count,unsigned live,unsigned cell,unsigned lane) {
    if(cell>=live)return 0;
    unsigned lo=0,hi=count;
    while(lo<hi) {const unsigned mid=(lo+hi)/2;if(tiles[mid].end<=cell)lo=mid+1;else hi=mid;}
    const auto t=tiles[lo];const auto s=norms[t.norm];const unsigned k=cell-t.first;
    const unsigned row=t.row+k/t.cols,col=t.col+k%t.cols;
    const uint64_t index=uint64_t(row)*s.columns+col;
    if(lane<s.pbytes)return payload[s.product+index*s.pbytes+lane];
    if(lane<s.pbytes+6)return payload[s.statistic+uint64_t(row)*6+lane-s.pbytes];
    if(lane<s.pbytes+8)return payload[s.output+index*2+lane-s.pbytes-6];
    return 0;
}
__device__ Fp3 factored(const Fp3* eq,unsigned bits,unsigned i) {
    const unsigned low=bits-bits/2;
    return mul6(eq[i>>low],eq[(1u<<(bits/2))+(i&((1u<<low)-1))]);
}
__global__ void eq_factors(const Fp3* point,unsigned bits,Fp3* out) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x,high=bits/2,low=bits-high;
    if(i<(1u<<high))out[i]=equality(point,high,i);
    if(i<(1u<<low))out[(1u<<high)+i]=equality(point+high,low,i);
}
__device__ Fp3 fixed_equality(Shape s,const Fp3* meta) {
    Fp3 v{1,0,0};
    for(unsigned i=0;i<s.round;++i)
        v=mul6(v,add(mul6(sub(Fp3{1,0,0},meta[i]),sub(Fp3{1,0,0},meta[prefix+i])),
                    mul6(meta[i],meta[prefix+i])));
    return v;
}
__global__ void baseline_coefficients(Shape s,const Fp3* meta,Fp3* out) {
    if(threadIdx.x || blockIdx.x)return;
    Fp3 value{};
    for(unsigned lane=0;lane<lanes;++lane)value=add(value,mul6(meta[lane_eq+lane],meta[baseline+lane]));
    value=mul6(value,fixed_equality(s,meta));const auto at=meta[s.round];
    out[0]=mul6(sub(Fp3{1,0,0},at),value);
    out[1]=mul6(sub(add(at,at),Fp3{1,0,0}),value);out[2]={};out[3]={};
}
// A whole warp follows the same public source positions. Only lane zero reads
// a source byte, then broadcasts it; no private byte decides a loop bound.
__device__ void regenerated(Shape s,unsigned lane,unsigned feature,unsigned key,
    const uint8_t* payload,const SourceNorm* norms,const SourceTile* tiles,
    unsigned tile_count,unsigned live,const Fp3* meta,const Fp3* eq,Fp3& x) {
    const unsigned thread=threadIdx.x&31,current=1u<<(s.bits-s.round);
    const auto* lut=meta+feature_lut+uint64_t(feature)*257+1;
    x=lut[0];
    for(unsigned at=0;at<(1u<<s.round);++at) {
        unsigned b=thread?0:source_byte(payload,norms,tiles,tile_count,live,at*current+key,lane);
        b=__shfl_sync(0xffffffffu,b,0);const auto w=factored(eq,s.round,at);
        x=add(x,mul6(w,sub(lut[b],lut[0])));
    }
}
__global__ void regenerate_rows(Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned tile_count,unsigned live,const Fp3* meta,
    const FeatureRange* ranges,const Fp3* eq,unsigned first,unsigned n,Fp3* state) {
    const unsigned warp=threadIdx.x/32,thread=threadIdx.x&31;
    const unsigned task=blockIdx.x*4+warp,pair=task/s.live_lanes,lane=task%s.live_lanes;
    if(pair>=n)return;
    const auto range=ranges[lane];
    // Every lane participates in broadcasts, including unused feature lanes.
    const unsigned f=range.first+(thread<range.count?thread:0);
    if(!range.count)return;
    Fp3 x{};regenerated(s,lane,f,first+pair,payload,norms,tiles,tile_count,live,meta,eq,x);
    if(thread<range.count)state[uint64_t(f)*s.stride+first+pair]=x;
}
__global__ void fold_features(Shape s,Fp3 r,Fp3* state) {
    const uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x,half=s.rows/2;
    if(i>=uint64_t(s.features)*half)return;
    const unsigned key=i%half,feature=i/half;
    const auto at=uint64_t(feature)*s.stride+key;
    state[at]=fold(state[at],state[at+half],r);
}
__global__ void cell_pairs(Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned tile_count,unsigned live,const Fp3* meta,
    const FeatureRange* ranges,const Fp3* prefix_eq,const Fp3* suffix_eq,
    const Fp3* state,unsigned first,unsigned n,Fp3* partials) {
    __shared__ Cubic sums[4];const unsigned warp=threadIdx.x/32,thread=threadIdx.x&31;
    const unsigned task=blockIdx.x*4+warp,pair=task/s.live_lanes,lane=task%s.live_lanes;
    Cubic value{};
    if(pair<n) {
        const auto range=ranges[lane];const unsigned key=first+pair,half=1u<<(s.bits-s.round-1);
        Fp3 q[3]{};
        if(range.count) {
            const unsigned feature=range.first+(thread<range.count?thread:0);
            Fp3 a{},b{};
            if(s.round<s.checkpoint) {
                regenerated(s,lane,feature,key,payload,norms,tiles,tile_count,live,meta,prefix_eq,a);
                regenerated(s,lane,feature,key+half,payload,norms,tiles,tile_count,live,meta,prefix_eq,b);
            } else if(thread<range.count) {
                const auto at=uint64_t(feature)*s.stride+key;
                a=state[at];b=state[at+half];
            }
            if(thread<range.count) {
                const auto weight=meta[feature_lut+uint64_t(feature)*257];
                const auto d=sub(b,a),da=mul6(weight,a),dd=mul6(weight,d),cross=mul6(da,d);
                q[0]=mul6(da,a);q[1]=add(cross,cross);q[2]=mul6(dd,d);
            }
        }
        for(unsigned step=16;step;step/=2)for(auto& v:q)v=add(v,shuffled(v,step));
        if(!thread) {
            q[0]=sub(q[0],meta[baseline+lane]);
            const auto weight=mul6(meta[lane_eq+lane],mul6(fixed_equality(s,meta),
                factored(suffix_eq,s.bits-s.round-1,key)));
            const auto at=meta[s.round],a=sub(Fp3{1,0,0},at),d=sub(add(at,at),Fp3{1,0,0});
            for(unsigned j=0;j<3;++j) {q[j]=mul6(weight,q[j]);
                value.c[j]=add(value.c[j],mul6(a,q[j]));value.c[j+1]=add(value.c[j+1],mul6(d,q[j]));}
        }
    }
    if(!thread)sums[warp]=value;__syncthreads();
    if(threadIdx.x<4) {Fp3 v{};for(unsigned w=0;w<4;++w)v=add(v,sums[w].c[threadIdx.x]);
        partials[uint64_t(blockIdx.x)*4+threadIdx.x]=v;}
}
__global__ void add_partials(const Fp3* partials,unsigned n,Fp3* out) {
    __shared__ Fp3 values[256];const unsigned tid=threadIdx.x,c=blockIdx.x;Fp3 v{};
    for(unsigned i=tid;i<n;i+=256)v=add(v,partials[uint64_t(i)*4+c]);values[tid]=v;__syncthreads();
    for(unsigned step=128;step;step/=2) {if(tid<step)values[tid]=add(values[tid],values[tid+step]);__syncthreads();}
    if(!tid)out[c]=add(out[c],values[0]);
}
__global__ void byte_histogram(Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned tile_count,unsigned live,const Fp3* eq,
    unsigned first,unsigned n,Fp3* partials) {
    __shared__ uint8_t bytes[256];__shared__ Fp3 weights[256];
    const unsigned lane=blockIdx.y,tid=threadIdx.x,cell=first+blockIdx.x*256+tid;
    bytes[tid]=cell<first+n?source_byte(payload,norms,tiles,tile_count,live,cell,lane):0;
    weights[tid]=cell<first+n?factored(eq,s.bits,cell):Fp3{};__syncthreads();
    Fp3 v{};for(unsigned i=0;i<256;++i)if(bytes[i]==tid)v=add(v,weights[i]);
    partials[(uint64_t(lane)*histogram_groups+blockIdx.x)*256+tid]=v;
}
__global__ void add_histograms(const Fp3* partials,unsigned groups,Fp3* hist) {
    const unsigned lane=blockIdx.x,bin=threadIdx.x;Fp3 v{};
    for(unsigned g=0;g<groups;++g)v=add(v,partials[(uint64_t(lane)*histogram_groups+g)*256+bin]);
    hist[lane*256+bin]=add(hist[lane*256+bin],v);
}
__global__ void padding_histogram(Shape s,const Fp3* prefix_point,unsigned live,Fp3* hist) {
    if(threadIdx.x || blockIdx.x)return;
    // Sum Eq over [0,live) without division, including zero/one coordinates.
    Fp3 mass{},equal{1,0,0};
    if(live==(1u<<s.bits))mass={1,0,0};
    else for(unsigned i=0;i<s.bits;++i) {
        const auto r=prefix_point[i];
        if((live>>(s.bits-1-i))&1) {mass=add(mass,mul6(equal,sub(Fp3{1,0,0},r)));equal=mul6(equal,r);}
        else equal=mul6(equal,sub(Fp3{1,0,0},r));
    }
    for(unsigned lane=0;lane<lanes;++lane) {
        if(lane>=s.live_lanes)hist[lane*256]={1,0,0};
        else hist[lane*256]=add(hist[lane*256],sub(Fp3{1,0,0},mass));
    }
}
__global__ void original_children(Shape s,const Fp3* meta,const Fp3* hist,Fp3* children) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x,count=2u<<s.layer;
    if(i>=lanes*count)return;
    const unsigned lane=i/count,node=i%count,width=256/count,first=node*width;
    Fp3 num{},den{};const auto* coeff=meta+coefficients+lane*256;
    for(unsigned b=0;b<256;++b) {
        // The associative original fraction-tree merge, no inversion or
        // assumption that denominators at a byte are nonzero.
        Pair value{Fp3{},Fp3{1,0,0}};
        for(unsigned j=first;j<first+width;++j)value=merge(value,Pair{coeff[j],integer(int64_t(b)-j)});
        num=add(num,mul6(hist[lane*256+b],value.p));den=add(den,mul6(hist[lane*256+b],value.q));
    }
    children[2*i]=num;children[2*i+1]=den;
}
__global__ void fold_recovered(unsigned rows,Fp3 r,Fp3* children) {
    const unsigned i=blockIdx.x*blockDim.x+threadIdx.x,half=rows/2;
    if(i<half*4)children[i]=fold(children[i],children[half*4+i],r);
}
__global__ void recovered_coefficients(Shape s,const Fp3* meta,const Fp3* children,Fp3* partials) {
    __shared__ Cubic sums[128];const unsigned i=blockIdx.x*128+threadIdx.x,half=s.rows/2;Cubic v{};
    if(i<half) {
        Children a{},b{};for(unsigned j=0;j<4;++j){a.v[j]=children[i*4+j];b.v[j]=children[(half+i)*4+j];}
        const unsigned total=s.bits+4+s.layer;const auto fixed=fixed_equality(s,meta);
        const auto lo=mul6(fixed,mul6(sub(Fp3{1,0,0},meta[s.round]),equality(meta+s.round+1,total-s.round-1,i)));
        const auto hi=mul6(fixed,mul6(meta[s.round],equality(meta+s.round+1,total-s.round-1,i)));
        v=c71_range::coefficients(a,b,meta[lambda],lo,hi);
    }
    sums[threadIdx.x]=v;__syncthreads();
    for(unsigned step=64;step;step/=2){if(threadIdx.x<step)sums[threadIdx.x]=sum(sums[threadIdx.x],sums[threadIdx.x+step]);__syncthreads();}
    if(!threadIdx.x)for(unsigned j=0;j<4;++j)partials[uint64_t(blockIdx.x)*4+j]=sums[0].c[j];
}
}
cudaError_t factors(cudaStream_t stream,const Fp3* point,unsigned bits,Fp3* out) {
    eq_factors<<<((1u<<(bits-bits/2))+127)/128,128,0,stream>>>(point,bits,out);return cudaGetLastError();
}
cudaError_t cell_baseline(cudaStream_t stream,Shape s,const Fp3* meta,Fp3* out) {
    baseline_coefficients<<<1,1,0,stream>>>(s,meta,out);return cudaGetLastError();
}
cudaError_t regenerate(cudaStream_t stream,Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned count,unsigned live,const Fp3* meta,const FeatureRange* ranges,
    const Fp3* eq,unsigned first,unsigned n,Fp3* state) {
    regenerate_rows<<<(n*s.live_lanes+3)/4,128,0,stream>>>(s,payload,norms,tiles,count,live,meta,ranges,eq,first,n,state);return cudaGetLastError();
}
cudaError_t fold_state(cudaStream_t stream,Shape s,Fp3 r,Fp3* state) {
    const auto count=uint64_t(s.features)*(s.rows/2);fold_features<<<(count+127)/128,128,0,stream>>>(s,r,state);return cudaGetLastError();
}
cudaError_t cell_coefficients(cudaStream_t stream,Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned count,unsigned live,const Fp3* meta,const FeatureRange* ranges,
    const Fp3* peq,const Fp3* seq,const Fp3* state,unsigned first,unsigned n,Fp3* partials) {
    cell_pairs<<<(n*s.live_lanes+3)/4,128,0,stream>>>(s,payload,norms,tiles,count,live,meta,ranges,peq,seq,state,first,n,partials);return cudaGetLastError();
}
cudaError_t sum_partials(cudaStream_t stream,const Fp3* partials,unsigned n,Fp3* out) {
    add_partials<<<4,256,0,stream>>>(partials,n,out);return cudaGetLastError();
}
cudaError_t histogram(cudaStream_t stream,Shape s,const uint8_t* payload,const SourceNorm* norms,
    const SourceTile* tiles,unsigned count,unsigned live,const Fp3* eq,unsigned first,unsigned n,Fp3* partials) {
    byte_histogram<<<dim3((n+255)/256,s.live_lanes),256,0,stream>>>(s,payload,norms,tiles,count,live,eq,first,n,partials);return cudaGetLastError();
}
cudaError_t histogram_sum(cudaStream_t stream,const Fp3* partials,unsigned groups,unsigned live_lanes,Fp3* hist) {
    add_histograms<<<live_lanes,256,0,stream>>>(partials,groups,hist);return cudaGetLastError();
}
cudaError_t histogram_padding(cudaStream_t stream,Shape s,const Fp3* point,unsigned live,Fp3* hist) {
    padding_histogram<<<1,1,0,stream>>>(s,point,live,hist);return cudaGetLastError();
}
cudaError_t recover(cudaStream_t stream,Shape s,const Fp3* meta,const Fp3* hist,Fp3* children) {
    original_children<<<(lanes*(2u<<s.layer)+127)/128,128,0,stream>>>(s,meta,hist,children);return cudaGetLastError();
}
cudaError_t fold_children(cudaStream_t stream,unsigned rows,Fp3 r,Fp3* children) {
    fold_recovered<<<(rows*2+127)/128,128,0,stream>>>(rows,r,children);return cudaGetLastError();
}
cudaError_t child_coefficients(cudaStream_t stream,Shape s,const Fp3* meta,const Fp3* children,Fp3* partials) {
    recovered_coefficients<<<(s.rows/2+127)/128,128,0,stream>>>(s,meta,children,partials);return cudaGetLastError();
}
}

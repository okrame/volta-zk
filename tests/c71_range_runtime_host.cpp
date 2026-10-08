// Tests the real owner with a deferred fake driver, NOT GPU math/execution.
#include "c71_range_runtime.h"
#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
#include <algorithm>
#include <cmath>
#include "c71_fft.cuh"
using namespace c71_range;
struct FakeStream { std::vector<std::function<void()>> pending; };
static bool fail_launch=false, fail_fence=false, fail_free=false, corrupt=false;
static bool fail_dense=false;
static int copy_fail_after=-1;
static int download_fail_after=-1;
static size_t fake_free=80000000000ULL;
static unsigned allocations=0, frees=0, launches=0;
static std::vector<uint8_t> expected_bytes;
static std::vector<int64_t> expected_raw;
static std::vector<uint64_t> expected_pcs;
cudaError_t cudaSetDevice(int n) { return n==0?0:1; }
cudaError_t cudaStreamCreateWithFlags(cudaStream_t* s,unsigned flags) {
    assert(flags==cudaStreamNonBlocking); *s=new FakeStream; return 0;
}
cudaError_t cudaStreamSynchronize(cudaStream_t s) {
    for(auto& f:s->pending) f();
    s->pending.clear();
    return fail_fence?1:0;
}
cudaError_t cudaStreamDestroy(cudaStream_t s) { assert(s->pending.empty()); delete s; return 0; }
cudaError_t cudaMalloc(void** p,size_t n) { ++allocations; *p=new unsigned char[n]; return 0; }
cudaError_t cudaMemGetInfo(size_t* free,size_t* total) { *free=fake_free; *total=80000000000ULL; return 0; }
cudaError_t cudaFree(void* p) {
    ++frees; delete[] static_cast<unsigned char*>(p); return fail_free?1:0;
}
cudaError_t cudaMemcpyAsync(void* d,const void* s,size_t n,cudaMemcpyKind kind,cudaStream_t stream) {
    if(kind==cudaMemcpyDeviceToHost) {
        if(download_fail_after==0) return 1;
        if(download_fail_after>0) --download_fail_after;
    }
    if(kind==cudaMemcpyDeviceToDevice) {
        if(copy_fail_after==0) return 1;
        if(copy_fail_after>0) --copy_fail_after;
    }
    stream->pending.push_back([=] { std::memcpy(d,s,n); if(kind==cudaMemcpyDeviceToHost && corrupt) {
        if(n>=8) *static_cast<uint64_t*>(d)=P; else *static_cast<uint32_t*>(d)=1;
    } });
    return 0;
}
cudaError_t cudaMemsetAsync(void* p,int x,size_t n,cudaStream_t s) {
    s->pending.push_back([=] { std::memset(p,x,n); }); return 0;
}
const char* cudaGetErrorString(cudaError_t) { return "injected CUDA failure"; }
static int launch(cudaStream_t s,std::function<void()> operation) {
    ++launches; if(fail_launch) return 1;
    s->pending.push_back(std::move(operation)); return 0;
}
extern "C" int c71_pcs_hash_launch(cudaStream_t stream,unsigned operation,const uint64_t* ring,
    const uint64_t* salts,c71_pcs::Hash32* states,uint64_t rows,uint64_t first,uint64_t count,
    unsigned column,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t local=0;local<count;++local) {
            const uint64_t row=first+local;
            for(unsigned j=0;j<(operation==1?8u:4u);++j) if(ring[j*rows+row]>=P) *failed=1;
            if(operation==0) states[row]=c71_pcs::leaf_start(ring,rows,row);
            else if(operation==1) states[row]=c71_pcs::leaf_step(states[row],ring+4*rows,ring,rows,row,column);
            else {
                for(unsigned j=0;j<4;++j) if(salts[j*count+local]>=P) *failed=1;
                states[row]=c71_pcs::leaf_finish(states[row],ring,salts,rows,row,count,local);
            }
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_nodes_launch(cudaStream_t stream,const c71_pcs::Hash32* input,
    c71_pcs::Hash32* output,uint64_t count,uint64_t rows) {
    return launch(stream,[=] { for(uint64_t i=0;i<count;++i) {
        const uint64_t left=2*(i/rows)*rows+i%rows;
        output[i]=c71_pcs::node(input[left],input[left+rows]);
    } });
}
extern "C" int c71_pcs_merge_launch(cudaStream_t stream,c71_pcs::Hash32* frontier,
    c71_pcs::Hash32* roots,uint64_t rows,unsigned group,unsigned levels) {
    return launch(stream,[=] { for(uint64_t row=0;row<rows;++row)
        c71_pcs::merge_group(frontier,roots,rows,row,group,levels); });
}
extern "C" int c71_pcs_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,c71_pcs::WeightShape s) {
    return launch(stream,[=] {
        const uint64_t omega=c71_pcs::power(7,(P-1)/(s.rows*s.cosets));
        for(unsigned lane=0;lane<32;++lane) {
            for(uint64_t row=0;row<s.rows;++row) low[lane*s.rows+row]=c71_pcs::power(omega,(s.first_coset+lane)*row);
            for(uint64_t q=0;q<c71_pcs::high_rows(s);++q) high[q*32+lane]=c71_pcs::power(omega,(s.first_coset+lane)*q*s.rows);
        }
    });
}
extern "C" int c71_pcs_twiddles_launch(cudaStream_t stream,uint64_t* output,unsigned log_rows) {
    return launch(stream,[=] {
        const uint64_t rows=uint64_t{1}<<log_rows,root=c71_pcs::power(7,(P-1)/rows);
        for(uint64_t row=0;row<rows;++row) output[row]=c71_pcs::power(root,row);
    });
}
extern "C" int c71_pcs_weight_launch(cudaStream_t stream,const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,const uint64_t* high,
    uint64_t* ring,c71_pcs::WeightShape s,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<32;++lane) for(uint64_t row=0;row<s.rows;++row)
            ring[(s.slots+column)*32*s.rows+lane*s.rows+row]=c71_pcs::accumulate(
                weights,tiles,tile_count,live,pads,low,high,s,s.first_column+column,row,lane);
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_fft_launch(cudaStream_t stream,uint64_t* values,const uint64_t* twiddles,
    unsigned log_rows,unsigned batch,unsigned* attempted) {
    *attempted+=5;
    return launch(stream,[=] {
        const size_t rows=size_t{1}<<log_rows, side=size_t{1}<<(log_rows/2);
        for(unsigned b=0;b<batch;++b) {
            std::vector<uint64_t> current(values+b*rows,values+(b+1)*rows);
            c71_fft::five_pass_fft(current,side,twiddles[1]);
            std::copy(current.begin(),current.end(),values+b*rows);
        }
        if(!expected_pcs.empty()) {
            assert(expected_pcs.size()==batch*rows);
            assert(std::memcmp(values,expected_pcs.data(),batch*rows*8)==0);
            expected_pcs.clear();
        }
    });
}
// Host arithmetic for cross-language protocol parity. This executes neither
// CUDA kernels nor their thread scheduling; it is never a production fallback.
static Pair fraction(const void* input,unsigned kind,size_t first,size_t n,Fp3 alpha) {
    if(n==1) {
        const int64_t x=kind?static_cast<const int16_t*>(input)[first]:static_cast<const uint8_t*>(input)[first];
        return {{1,0,0},sub(alpha,integer(x))};
    }
    return merge(fraction(input,kind,first,n/2,alpha),fraction(input,kind,first+n/2,n/2,alpha));
}
extern "C" int c71_range_launch_roots(cudaStream_t s,unsigned kind,const void* input,size_t,unsigned bottom,Fp3 alpha,Pair* p,size_t n) {
    return launch(s,[=] {
        if(!expected_bytes.empty()) {
            assert(kind==0 && expected_bytes.size()==(n<<bottom));
            assert(std::memcmp(input,expected_bytes.data(),expected_bytes.size())==0);
            expected_bytes.clear();
        }
        for(size_t i=0;i<n;++i) p[i]=fraction(input,kind,i<<bottom,size_t{1}<<bottom,alpha);
    });
}
extern "C" int c71_range_launch_groups(cudaStream_t s,unsigned kind,const void* input,size_t words,Group g,Children* p,size_t,Fp3* h,size_t) {
    return launch(s,[=] {
        const size_t length=size_t{1}<<g.width, subtree=size_t{1}<<g.bottom, old_count=size_t{1}<<g.prefix_bits;
        for(size_t t=0;t<words/(length*subtree*old_count);++t) {
            Children bucket[32]{};
            for(size_t u=0;u<length;++u) for(size_t old=0;old<old_count;++old) {
                const size_t first=((t*old_count+old)*length+u)*subtree;
                const auto a=fraction(input,kind,first,subtree/2,g.alpha), b=fraction(input,kind,first+subtree/2,subtree/2,g.alpha);
                const Fp3 child[]={a.p,a.q,b.p,b.q},weight=equality(g.prefix,g.prefix_bits,old);
                for(unsigned j=0;j<4;++j) bucket[u].v[j]=add(bucket[u].v[j],mul6(weight,child[j]));
            }
            const size_t tail=g.first_tail+t;
            if(!g.width) p[tail]=bucket[0];
            else for(size_t u=0;u<length;++u) for(size_t v=0;v<length;++v) {
                auto& cell=h[(tail%g.buckets)*length*length+u*length+v];
                cell=add(cell,gram(bucket[u],bucket[v],g.lambda,equality(g.tail_point,g.tail_bits,tail)));
            }
        }
    });
}
extern "C" int c71_range_launch_canopy(cudaStream_t s,const Pair* a,Pair* p,size_t n) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) p[i]=merge(a[2*i],a[2*i+1]); });
}
extern "C" int c71_range_launch_h_sum(cudaStream_t s,const Fp3* a,Fp3* p,unsigned n,unsigned buckets) {
    return launch(s,[=] { for(unsigned i=0;i<n;++i) { p[i]={}; for(unsigned b=0;b<buckets;++b) p[i]=add(p[i],a[b*n+i]); } });
}
extern "C" int c71_range_launch_h_fold(cudaStream_t s,const Fp3* a,Fp3* p,unsigned half,Fp3 r) {
    return launch(s,[=] { const unsigned n=2*half; for(unsigned i=0;i<half;++i) for(unsigned j=0;j<half;++j)
        p[i*half+j]=fold(fold(a[i*n+j],a[i*n+j+half],r),fold(a[(i+half)*n+j],a[(i+half)*n+j+half],r),r); });
}
extern "C" int c71_range_launch_child_fold(cudaStream_t s,Children* p,size_t n,Fp3 r) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) p[i]=fold(p[i],p[i+n],r); });
}
extern "C" int c71_range_launch_coefficients(cudaStream_t s,const Children* a,size_t half,Round r,Cubic* p) {
    return launch(s,[=] { for(size_t i=0;i<half;++i) {
        if(i%256==0) p[i/256]={};
        p[i/256]=sum(p[i/256],coefficients(a[i],a[i+half],r.lambda,
            mul6(r.prefix_equality,equality(r.point,r.bits,i)),mul6(r.prefix_equality,equality(r.point,r.bits,i+half))));
    } });
}
extern "C" int c71_range_launch_reduce(cudaStream_t s,const Cubic* a,size_t n,Cubic* p) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) { if(i%256==0) p[i/256]={}; p[i/256]=sum(p[i/256],a[i]); } });
}
extern "C" int c71_range_launch_h_coefficients(cudaStream_t s,const Fp3* a,unsigned half,Round r,Cubic* p) {
    return launch(s,[=] { *p=h_coefficients(a,half,r); });
}
extern "C" int c71_dense_i16_launch(cudaStream_t s,const int16_t* x,uint64_t nx,const int16_t* w,uint64_t nw,
    int64_t* out,uint64_t no,uint32_t* failed,c71_dense::Shape shape) {
    assert(c71_dense::valid_buffers(x,nx,w,nw,out,no,failed,shape));
    return launch(s,[=] {
        for(unsigned i=0;i<shape.m;++i) for(unsigned j=0;j<shape.n;++j) {
            int64_t sum=0;
            for(unsigned k=0;k<shape.k;++k) {
                const auto a=x[size_t(i)*shape.k+k], b=w[size_t(j)*shape.k+k];
                if(a==INT16_MIN || b==INT16_MIN) *failed=1;
                sum+=int64_t(a)*b;
            }
            out[size_t(i)*shape.n+j]=sum;
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_dense_rne_launch(cudaStream_t s,const int64_t* raw,int16_t* out,uint64_t count,
    int32_t shift,uint32_t* failed) {
    return launch(s,[=] {
        if(!expected_raw.empty()) {
            assert(expected_raw.size()==count && std::memcmp(raw,expected_raw.data(),count*8)==0);
            expected_raw.clear();
        }
        for(uint64_t i=0;i<count;++i) if(!c71_dense::quantize(raw[i],shift,out[i])) *failed=1;
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_byte_scatter_launch(cudaStream_t s,const void* input,unsigned kind,uint64_t input_count,
    uint8_t* output,uint64_t output_count,uint32_t* failed,c71_byte::Tile t) {
    assert(c71_byte::valid(t,kind,input_count,output_count));
    return launch(s,[=] {
        if(!expected_raw.empty()) {
            assert(expected_raw.size()==input_count);
            for(uint64_t index=0;index<input_count;++index) {
                const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
                assert(value==expected_raw[index]);
            }
            expected_raw.clear();
        }
        for(uint64_t i=0;i<t.rows*t.columns*t.width;++i) {
            const uint64_t address=c71_byte::ordered(t.original_first+i,t);
            if(address<t.window_first || address-t.window_first>=t.window_length) continue;
            const uint64_t word=i/t.width, index=t.input_first+(word/t.columns)*t.input_stride+word%t.columns;
            const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
            uint8_t byte=0;
            if(!c71_byte::encode(value,t.signed_width,t.byte_first+i%t.width,byte)) *failed=1;
            else output[address-t.window_first]=byte;
        }
    });
}
extern "C" int c71_dense_pointwise_launch(cudaStream_t s,const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,c71_dense::Pointwise op,uint32_t* failed) {
    assert(c71_dense::valid_pointwise(op));
    return launch(s,[=] {
        for(uint64_t i=0;i<count;++i) {
            const int16_t a=(op.multiply || op.a)?x[i]:0, b=(op.multiply || op.b)?y[i]:0;
            if(!c71_dense::pointwise(a,b,op,output[i])) *failed=1;
        }
    });
}

extern "C" int c71_lookup_launch(cudaStream_t stream,const int16_t* input,const int16_t* table,
    int16_t* output,int64_t* histogram,uint64_t count,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t index=0;index<count;++index) {
            int16_t value; uint32_t entry;
            if(!c71_nonlinear::lookup(input[index],table,value,entry)) *failed=1;
            else { output[index]=value; ++histogram[entry]; }
        }
    });
}
extern "C" int c71_histogram_seal_launch(cudaStream_t stream,int64_t* histogram,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned entry=0;entry<65535;++entry) {
            if(histogram[entry]<0 || histogram[entry]>INT32_MAX) *failed=1;
        }
    });
}
extern "C" int c71_rope_launch(cudaStream_t stream,const int16_t* input,const int32_t* coefficients,
    int64_t* output,c71_nonlinear::Rope shape,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<shape.rows;++row) for(unsigned head=0;head<shape.heads;++head)
            for(unsigned pair=0;pair<shape.width/2;++pair) {
                const auto first=(uint64_t(row)*shape.heads+head)*shape.width+pair,second=first+shape.width/2;
                const int32_t cosine=pair<shape.pairs?coefficients[(row*shape.pairs+pair)*2]:1<<30;
                const int32_t sine=pair<shape.pairs?coefficients[(row*shape.pairs+pair)*2+1]:0;
                if(!c71_nonlinear::rotate(input[first],input[second],cosine,sine,output[first],output[second])) *failed=1;
            }
    });
}
extern "C" int c71_argmax_select_launch(cudaStream_t stream,const int16_t* input,uint32_t* tokens,
    unsigned rows,unsigned columns,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<rows;++row) {
            unsigned best=0;
            for(unsigned column=0;column<columns;++column) {
                if(input[uint64_t(row)*columns+column]==INT16_MIN) *failed=1;
                if(input[uint64_t(row)*columns+column]>input[uint64_t(row)*columns+best]) best=column;
            }
            tokens[row]=best;
        }
    });
}
extern "C" int c71_argmax_slack_launch(cudaStream_t stream,const int16_t* input,const uint32_t* tokens,
    int16_t* output,unsigned rows,unsigned columns,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<rows;++row) for(unsigned column=0;column<columns;++column) {
            const auto index=uint64_t(row)*columns+column;
            if(tokens[row]>=columns || !c71_nonlinear::slack(input[uint64_t(row)*columns+tokens[row]],
                input[index],column,tokens[row],output[index])) *failed=1;
        }
    });
}

extern "C" int c71_rms_launch(cudaStream_t stream,const int16_t* input,const int16_t* weights,
    int64_t* products,int64_t* statistics,int16_t* output,c71_nonlinear::Rms shape,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<shape.rows*shape.heads;++row) {
            int64_t sum=0;
            for(unsigned column=0;column<shape.columns;++column) {
                const int64_t value=input[uint64_t(row)*shape.columns+column];
                if(value==INT16_MIN) *failed=1;
                sum+=value*value;
            }
            statistics[row]=sum;
            for(unsigned column=0;column<shape.columns;++column) {
                const auto index=uint64_t(row)*shape.columns+column;
                const int16_t weight=shape.weighted?weights[column]:1;
                const int64_t product=int64_t(input[index])*weight;
                if(weight==INT16_MIN || !c71_nonlinear::rms_round(shape,product,sum,output[index])) *failed=1;
                if(shape.weighted) products[index]=product;
            }
        }
    });
}
extern "C" int c71_qk_launch(cudaStream_t stream,const int16_t* query,const int16_t* keys,int64_t* output,
    c71_nonlinear::Attention shape,uint32_t* failed) {
    return launch(stream,[=] {
        const unsigned columns=shape.old+150,group=shape.head/(32/shape.groups);
        for(unsigned row=0;row<shape.rows;++row) for(unsigned key=0;key<columns;++key) {
            int64_t sum=0;
            if(key<=shape.old+shape.first+row) for(unsigned lane=0;lane<shape.lanes;++lane) {
                const int16_t left=query[(uint64_t(row)*32+shape.head)*shape.lanes+lane];
                const int16_t right=keys[(uint64_t(key)*shape.groups+group)*shape.lanes+lane];
                if(left==INT16_MIN || right==INT16_MIN) *failed=1;
                sum+=int64_t(left)*right;
            }
            output[uint64_t(row)*columns+key]=sum;
        }
    });
}
extern "C" int c71_pv_launch(cudaStream_t stream,const int16_t* const* probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention shape,uint32_t* failed) {
    std::vector<const int16_t*> pointers(probabilities,probabilities+32);
    return launch(stream,[=] {
        const unsigned columns=shape.old+150;
        for(unsigned row=0;row<shape.rows;++row) for(unsigned head=0;head<32;++head) for(unsigned lane=0;lane<shape.lanes;++lane) {
            int64_t sum=0;
            for(unsigned key=0;key<=shape.old+shape.first+row;++key) {
                const int16_t probability=pointers[head][uint64_t(row)*columns+key];
                const int16_t value=values[(uint64_t(key)*shape.groups+head/(32/shape.groups))*shape.lanes+lane];
                if(probability<0 || probability>16384 || value==INT16_MIN) *failed=1;
                sum+=int64_t(probability)*value;
            }
            output[(uint64_t(row)*32+head)*shape.lanes+lane]=sum;
        }
    });
}
extern "C" int c71_softmax_launch(cudaStream_t stream,const int16_t* scores,const int32_t* table,
    int16_t* maximum,int16_t* difference,int64_t* exponential,int64_t* denominator,int16_t* probabilities,
    int64_t* histogram,c71_nonlinear::Attention shape,uint32_t* failed) {
    return launch(stream,[=] {
        const unsigned columns=shape.old+150;
        for(unsigned row=0;row<shape.rows;++row) {
            const uint64_t first=uint64_t(row)*columns;
            const unsigned live=shape.old+shape.first+row+1;
            int16_t largest=INT16_MIN;
            for(unsigned column=0;column<columns;++column) {
                const int16_t value=scores[first+column];
                if(value==INT16_MIN || (column>=live && value!=0)) *failed=1;
                if(column<live && value>largest) largest=value;
            }
            maximum[row]=largest; int64_t sum=0;
            for(unsigned column=0;column<columns;++column) {
                const int delta=column<live?int(largest)-scores[first+column]:0;
                exponential[first+column]=0;
                if(delta<0 || delta>65534) { *failed=1; continue; }
                const int32_t value=table[delta];
                if(value<0 || value>(1<<30) || (delta==0 && value!=(1<<30))) { *failed=1; continue; }
                difference[first+column]=int16_t(delta-32767); exponential[first+column]=value; ++histogram[delta];
                if(column<live) sum+=value;
            }
            denominator[row]=sum;
            if(sum<(int64_t{1}<<30) || sum>int64_t(live)*(1<<30)) { *failed=1; continue; }
            for(unsigned column=0;column<columns;++column)
                probabilities[first+column]=column<live?c71_nonlinear::probability(int32_t(exponential[first+column]),sum):0;
        }
    });
}

#ifdef C71_RANGE_FFI_TEST
// Test library only; production exports neither error injection nor host math.
extern "C" void c71_range_test_expect_bytes(const uint8_t* p,uint64_t n) {
    assert(n && expected_bytes.empty()); expected_bytes.assign(p,p+n);
}
extern "C" void c71_range_test_expect_raw(const int64_t* p,uint64_t n) {
    assert(n && expected_raw.empty()); expected_raw.assign(p,p+n);
}
extern "C" void c71_range_test_expect_pcs(const uint64_t* p,uint64_t n) {
    assert(n && expected_pcs.empty()); expected_pcs.assign(p,p+n);
}
extern "C" void c71_range_test_failure(unsigned kind) {
    fail_launch=kind==1; fail_fence=kind==2; fail_free=kind==3; corrupt=kind==4;
    copy_fail_after=kind==5?0:kind==6?1:-1;
    download_fail_after=kind==7?0:kind==8?1:-1;
    fail_dense=kind==9;
}
#else

static C71RangeContext* create(uint64_t bytes=262144) {
    C71RangeContext* c=nullptr; assert(!c71_range_create(0,bytes,256,nullptr,&c)); return c;
}
static uint64_t alloc(C71RangeContext* c,unsigned kind,uint64_t n) {
    uint64_t id=0; assert(!c71_range_alloc(c,kind,n,&id)); return id;
}
static C71RangeStats stats(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_stats(c,&s)); return s; }
static void close(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_close(c,&s)); assert(!s.arena_bytes && !s.weights_bytes && !s.cleanup_failed); }
static uint64_t roots(C71RangeContext* c,unsigned kind=0,unsigned n=2048) {
    const auto in=alloc(c,kind,2*n), out=alloc(c,C71_PAIR,n);
    std::vector<int16_t> data(2*n,3);
    assert(!c71_range_upload(c,in,data.data(),2*n*(kind+1)));
    assert(!c71_range_roots(c,in,1,{5,2,3},out,0));
    assert(!c71_range_release(c,in)); return out;
}
static void install(C71RangeContext* c) {
    const int16_t w[]={123,321, 1,2,3,4, 4,3,2,1};
    assert(!c71_dense_weights_begin(c,10));
    assert(!c71_dense_weights_upload(c,0,w,3));
    assert(!c71_dense_weights_upload(c,3,w+3,7));
    assert(!c71_dense_weights_seal(c));
}
static uint64_t dense_input(C71RangeContext* c) {
    const auto x=alloc(c,C71_I16,8);
    const int16_t values[]={1,2,3,4,-1,-2,-3,-4};
    assert(!c71_range_upload(c,x,values,sizeof(values))); return x;
}
static void dense_checks() {
    auto* c=create(); install(c); const auto x=dense_input(c);
    const auto before=stats(c);
    assert(before.weights_bytes==20 && before.weights_loaded_bytes==20 && before.weights_sealed);
    assert(before.peak_reserved_bytes==before.arena_bytes+20);
    // Two batches, original W offset after a sentinel prefix. W is never
    // copied again; output stays device-resident into RNE and signed range.
    for(unsigned batch=0;batch<2;++batch) {
        const auto raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4), root=alloc(c,C71_PAIR,1);
        assert(!c71_dense_product(c,x,2,{2,2,4},raw));
        assert(!c71_dense_quantize(c,raw,2,y));
        assert(!c71_range_roots(c,y,2,{19,2,3},root,0));
        uint64_t limbs[6]{}; assert(!c71_range_read(c,root,limbs,6));
        const int16_t expected[]={8,5,-8,-5}; // 30/4 ties to even, 20/4 exact.
        const auto reference=fraction(expected,1,0,4,{19,2,3});
        assert(std::memcmp(limbs,&reference,sizeof(reference))==0);
        assert(!c71_range_release(c,root) && !c71_range_release(c,y) && !c71_range_release(c,raw));
        assert(stats(c).h2d_bytes==before.h2d_bytes);
        assert(stats(c).live_capacity_bytes==before.live_capacity_bytes);
        assert(stats(c).peak_capacity_bytes>=before.live_capacity_bytes+4*256);
    }
    assert(stats(c).d2h_bytes-before.d2h_bytes==2*(8+48));
    const auto selected_raw=alloc(c,C71_I64,2), selected_y=alloc(c,C71_I16,2), selected_root=alloc(c,C71_PAIR,1);
    assert(!c71_dense_product_rows(c,x,1,2,{1,2,4},selected_raw));
    assert(!c71_dense_quantize(c,selected_raw,2,selected_y));
    assert(!c71_range_roots(c,selected_y,1,{19,2,3},selected_root,0));
    uint64_t selected_limbs[6]{}; assert(!c71_range_read(c,selected_root,selected_limbs,6));
    const int16_t selected_expected[]={-8,-5};
    const auto selected_reference=fraction(selected_expected,1,0,2,{19,2,3});
    assert(std::memcmp(selected_limbs,&selected_reference,sizeof(selected_reference))==0);
    assert(stats(c).h2d_bytes==before.h2d_bytes);
    close(c);
    for(unsigned test=0;test<23;++test) {
        c=create(); int status=0;
        if(test<6) {
            const int16_t w[]={1,2,3,4};
            switch(test) {
            case 0: status=c71_dense_weights_begin(c,61394690560ULL/2+1); break;
            case 1: fake_free=uint64_t{1}<<30; status=c71_dense_weights_begin(c,4); fake_free=80000000000ULL; break;
            case 2: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_seal(c); break;
            case 3: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_upload(c,1,w,3); break;
            case 4: { const int16_t bad=INT16_MIN; assert(!c71_dense_weights_begin(c,1)); status=c71_dense_weights_upload(c,0,&bad,1); break; }
            case 5: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_begin(c,4); break;
            }
        } else {
            install(c); const auto x=dense_input(c), raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4);
            switch(test) {
            case 6: status=c71_dense_weights_upload(c,0,nullptr,1); break;
            case 7: status=c71_dense_product(c,x,UINT64_MAX,{2,2,4},raw); break;
            case 8: status=c71_dense_product(c,x,2,{3,2,4},raw); break;
            case 9: status=c71_dense_product(c,x,2,{2,2,4},x); break;
            case 10: status=c71_dense_quantize(c,raw,2,y); break;
            case 11: fail_launch=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_launch=false; break;
            case 12: fail_fence=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_fence=false; break;
            case 13: fail_dense=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_dense=false; break;
            case 14: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); status=c71_dense_quantize(c,raw,-15,y); break;
            case 15: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); status=c71_dense_product(c,x,2,{2,2,4},raw); break;
            case 16: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); fail_fence=true;
                status=c71_dense_quantize(c,raw,2,y); fail_fence=false; break;
            case 17: status=c71_dense_weights_seal(c); break;
            case 18: status=c71_dense_product(c,y,2,{2,2,4},raw); break;
            case 19: status=c71_dense_product_rows(c,x,UINT64_MAX,2,{2,2,4},raw); break;
            case 20: status=c71_dense_product_rows(c,x,1,2,{2,2,4},raw); break;
            case 21: status=c71_dense_product_rows(c,x,1,2,{1,2,4},raw); break; // output shape
            case 22: status=c71_range_abort(c); break;
            }
        }
        const auto attempts=launches;
        assert(status && stats(c).stopped && *c71_range_error(c));
        uint64_t ignored=0; assert(c71_range_alloc(c,C71_I16,1,&ignored));
        assert(c71_dense_weights_seal(c) && launches==attempts);
        close(c);
    }
    c=create(); install(c); fail_free=true; C71RangeStats final{};
    assert(c71_range_close(c,&final) && final.cleanup_failed && final.weights_bytes==20 && final.arena_bytes==0);
    fail_free=false;
}
static void embedding_checks() {
    auto* c=create(); install(c);
    for(unsigned rows: {1u,4u,150u}) {
        std::vector<uint32_t> ids(rows);
        for(unsigned i=0;i<rows;++i) ids[i]=(i%3==0)?1:0;
        const auto out=alloc(c,C71_I16,rows*4);
        const auto before=stats(c);
        assert(!c71_dense_embedding(c,2,2,4,ids.data(),rows,out));
        auto after=stats(c);
        assert(after.d2d_bytes-before.d2d_bytes==rows*8);
        assert(after.h2d_bytes==before.h2d_bytes && after.d2h_bytes==before.d2h_bytes);
        assert(after.launches==before.launches && after.allocations==before.allocations);
        assert(after.fences==before.fences+1);
        for(auto token:ids) for(int j=0;j<4;++j) expected_raw.push_back(token?4-j:j+1);
        const auto raw=alloc(c,C71_I64,rows*4), rounded=alloc(c,C71_I16,rows*4);
        assert(!c71_dense_pointwise(c,out,0,0,0,{1,0,0},raw));
        assert(!c71_dense_quantize(c,raw,0,rounded)); // exact ordered observation
        assert(expected_raw.empty());
        assert(!c71_range_release(c,raw) && !c71_range_release(c,rounded) && !c71_range_release(c,out));
        assert(stats(c).live_capacity_bytes==0);
    }
    close(c);
    for(unsigned test=0;test<17;++test) {
        c=create(); if(test!=0) install(c);
        const auto out=alloc(c,C71_I16,8);
        uint32_t tokens[]={0,1}; int status=0;
        switch(test) {
        case 0: status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 1: tokens[1]=2; status=c71_dense_embedding(c,2,2,4,tokens,2,out); assert(!stats(c).d2d_bytes); break;
        case 2: tokens[0]=UINT32_MAX; status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 3: status=c71_dense_embedding(c,UINT64_MAX,2,4,tokens,2,out); break;
        case 4: status=c71_dense_embedding(c,3,2,4,tokens,2,out); break;
        case 5: status=c71_dense_embedding(c,2,0,4,tokens,2,out); break;
        case 6: status=c71_dense_embedding(c,2,2,0,tokens,2,out); break;
        case 7: status=c71_dense_embedding(c,2,2,4,tokens,0,out); break;
        case 8: status=c71_dense_embedding(c,2,2,4,tokens,151,out); break;
        case 9: status=c71_dense_embedding(c,2,2,4,tokens,1,out); break;
        case 10: status=c71_dense_embedding(c,2,2,4,nullptr,2,out); break;
        case 11: assert(!c71_dense_embedding(c,2,2,4,tokens,2,out)); status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 12: { auto raw=alloc(c,C71_I64,8); status=c71_dense_embedding(c,2,2,4,tokens,2,raw); break; }
        case 13: copy_fail_after=0; status=c71_dense_embedding(c,2,2,4,tokens,2,out); copy_fail_after=-1; assert(!stats(c).d2d_bytes); break;
        case 14: copy_fail_after=1; status=c71_dense_embedding(c,2,2,4,tokens,2,out); copy_fail_after=-1; assert(stats(c).d2d_bytes==8); break;
        case 15: fail_fence=true; status=c71_dense_embedding(c,2,2,4,tokens,2,out); fail_fence=false; assert(stats(c).d2d_bytes==16); break;
        case 16: { auto* other=create(); auto foreign=alloc(other,C71_I16,8); status=c71_dense_embedding(c,2,2,4,tokens,2,foreign); close(other); break; }
        }
        assert(status && stats(c).stopped);
        const auto before=stats(c);
        assert(c71_dense_embedding(c,2,2,4,tokens,2,out));
        assert(stats(c).d2d_bytes==before.d2d_bytes && stats(c).launches==before.launches);
        close(c);
    }
}
static void pointwise_checks() {
    auto* c=create(); const auto x=dense_input(c);
    const c71_dense::Pointwise ops[]={{3,-2,0},{1,1,1},{0,2,0},{3,0,0},{0,0,0}};
    for(const auto op:ops) {
        const auto raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4), root=alloc(c,C71_PAIR,1);
        const auto before=stats(c);
        assert(!c71_dense_pointwise(c,op.a?x:0,op.a?4:0,op.b?x:0,0,op,raw));
        assert(!c71_dense_quantize(c,raw,0,y));
        int16_t expected[4];
        for(int i=0;i<4;++i) expected[i]=op.multiply?-(i+1)*(i+1):int16_t(-op.a*(i+1)+op.b*(i+1));
        const auto reference=fraction(expected,1,0,4,{19,2,3});
        assert(!c71_range_roots(c,y,2,{19,2,3},root,0));
        uint64_t limbs[6]; assert(!c71_range_read(c,root,limbs,6));
        assert(std::memcmp(limbs,&reference,sizeof(reference))==0);
        assert(stats(c).h2d_bytes==before.h2d_bytes && stats(c).d2h_bytes-before.d2h_bytes==56);
        assert(!c71_range_release(c,root) && !c71_range_release(c,y) && !c71_range_release(c,raw));
    }
    close(c);
    for(unsigned test=0;test<14;++test) {
        c=create(); const auto x=dense_input(c),raw=alloc(c,C71_I64,4); int status=0;
        switch(test) {
        case 0: status=c71_dense_pointwise(c,x,UINT64_MAX,x,0,{1,1,0},raw); break;
        case 1: status=c71_dense_pointwise(c,x,6,x,0,{1,1,0},raw); break;
        case 2: status=c71_dense_pointwise(c,x,0,x,0,{INT64_MIN,1,0},raw); break;
        case 3: status=c71_dense_pointwise(c,x,0,x,0,{1,1,2},raw); break;
        case 4: status=c71_dense_pointwise(c,x,0,x,0,{0,1,1},raw); break;
        case 5: status=c71_dense_pointwise(c,x,0,x,0,{0,1,0},raw); break;
        case 6: status=c71_dense_pointwise(c,0,0,x,0,{1,1,0},raw); break;
        case 7: status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},x); break;
        case 8: { auto empty=alloc(c,C71_I16,4); status=c71_dense_pointwise(c,empty,0,x,0,{1,1,0},raw); break; }
        case 9: assert(!c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw)); status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); break;
        case 10: fail_launch=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); fail_launch=false; break;
        case 11: fail_fence=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); fail_fence=false; break;
        case 12: corrupt=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); corrupt=false; break;
        case 13: { auto* other=create(); auto foreign=dense_input(other); status=c71_dense_pointwise(c,foreign,0,x,0,{1,1,0},raw); close(other); break; }
        }
        assert(status && stats(c).stopped);
        const auto attempts=launches;
        assert(c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw) && launches==attempts);
        close(c);
    }
}
static void byte_checks() {
    // Independent biased addition, including both signed-48 and signed-32 ends.
    for(unsigned width: {2u,4u,6u}) {
        const int64_t bound=int64_t{1}<<(8*width-1);
        for(int64_t value: {-bound,-bound+1,int64_t{-257},int64_t{-1},int64_t{0},int64_t{255},bound-1,bound}) {
            for(unsigned lane=0;lane<width;++lane) {
                uint8_t byte=99;
                const bool valid=value>=-bound && value<bound;
                assert(c71_byte::encode(value,width,lane,byte)==valid);
                if(valid) assert(byte==uint8_t(uint64_t(value+bound)>>(8*lane)));
            }
        }
    }
    const c71_byte::Tile base{0,4,2,4,32,0,128,0,2,2,7,2,1};
    auto* c=create(); const auto input=dense_input(c), out=alloc(c,C71_BYTE_PENDING,128);
    const auto before=stats(c);
    assert(!c71_byte_begin(c,out));
    assert(!c71_byte_scatter(c,input,&base,out));
    assert(stats(c).fences==before.fences && stats(c).d2h_bytes==before.d2h_bytes);
    // Producer lifetime ends before seal. Its reused allocation is ordered
    // AFTER the queued scatter, not an input copy hidden in the gather.
    assert(!c71_range_release(c,input));
    const auto replacement=alloc(c,C71_I16,8);
    const int16_t replacement_values[8]={99,99,99,99,99,99,99,99};
    assert(!c71_range_upload(c,replacement,replacement_values,sizeof(replacement_values)));
    assert(!c71_byte_seal(c,out));
    assert(stats(c).d2h_bytes-before.d2h_bytes==4 && stats(c).h2d_bytes==before.h2d_bytes+16);
    expected_bytes.assign(128,0);
    const int16_t values[]={1,2,3,4,-1,-2,-3,-4};
    for(unsigned i=0;i<16;++i) {
        const unsigned original=32+i;
        // Independent bit mapping: low subtree bit stays, next two move up.
        unsigned address=original&1;
        for(unsigned bit=1;bit<7;++bit) address|=((original>>bit)&1)<<(bit<3?bit+4:bit-2);
        expected_bytes[address]=uint8_t((int(values[i/2])+32768)>>(8*(i%2)));
    }
    const auto root=alloc(c,C71_PAIR,1);
    assert(!c71_range_roots(c,out,7,{19,2,3},root,0));
    uint64_t limbs[6]; assert(!c71_range_read(c,root,limbs,6));
    assert(expected_bytes.empty());
    close(c);
    for(unsigned test=0;test<19;++test) {
        c=create(); const auto x=dense_input(c), pending=alloc(c,C71_BYTE_PENDING,128);
        if(test!=1) assert(!c71_byte_begin(c,pending));
        auto t=base; int status=0;
        switch(test) {
        case 0: { auto r=alloc(c,C71_PAIR,1); status=c71_range_roots(c,pending,7,{19,2,3},r,0); break; }
        case 1: status=c71_byte_scatter(c,x,&t,pending); break;
        case 2: status=c71_byte_begin(c,pending); break;
        case 3: { auto empty=alloc(c,C71_I16,8); status=c71_byte_scatter(c,empty,&t,pending); break; }
        case 4: t.signed_width=6; status=c71_byte_scatter(c,x,&t,pending); break;
        case 5: t.original_first=UINT64_MAX; status=c71_byte_scatter(c,x,&t,pending); break;
        case 6: t.input_stride=0; status=c71_byte_scatter(c,x,&t,pending); break;
        case 7: t.input_first=UINT64_MAX; status=c71_byte_scatter(c,x,&t,pending); break;
        case 8: t.dimension=36; status=c71_byte_scatter(c,x,&t,pending); break;
        case 9: t.suffix=7; status=c71_byte_scatter(c,x,&t,pending); break;
        case 10: t.bottom=8; status=c71_byte_scatter(c,x,&t,pending); break;
        case 11: t.window_first=1; status=c71_byte_scatter(c,x,&t,pending); break;
        case 12: t.window_length=64; status=c71_byte_scatter(c,x,&t,pending); break;
        case 13: status=c71_byte_scatter(c,pending,&t,pending); break;
        case 14: assert(!c71_byte_seal(c,pending)); status=c71_byte_scatter(c,x,&t,pending); break;
        case 15: assert(!c71_byte_scatter(c,x,&t,pending)); fail_fence=true; status=c71_byte_seal(c,pending); fail_fence=false; break;
        case 16: assert(!c71_byte_scatter(c,x,&t,pending)); corrupt=true; status=c71_byte_seal(c,pending); corrupt=false; break;
        case 17: fail_launch=true; status=c71_byte_scatter(c,x,&t,pending); fail_launch=false; break;
        case 18: {
            const int16_t large[]={32767,32767,32767,32767};
            assert(!c71_dense_weights_begin(c,4));
            assert(!c71_dense_weights_upload(c,0,large,4)); assert(!c71_dense_weights_seal(c));
            const auto in=alloc(c,C71_I16,4), raw=alloc(c,C71_I64,1);
            assert(!c71_range_upload(c,in,large,sizeof(large)));
            assert(!c71_dense_product(c,in,0,{1,1,4},raw));
            const c71_byte::Tile narrow{0,1,1,1,0,0,128,0,4,4,7,0,0};
            assert(!c71_byte_scatter(c,raw,&narrow,pending));
            status=c71_byte_seal(c,pending); break; // actual device-codec flag
        }
        }
        assert(status && stats(c).stopped);
        const auto attempted=launches;
        assert(c71_byte_seal(c,pending) && launches==attempted);
        close(c);
    }
    // Releasing an unfinished window frees its flag and capacity after a fence.
    c=create(); const auto pending=alloc(c,C71_BYTE_PENDING,128);
    assert(!c71_byte_begin(c,pending)); assert(stats(c).live_capacity_bytes==512);
    assert(!c71_range_release(c,pending)); assert(!stats(c).live_capacity_bytes);
    close(c);
}
static uint64_t joint_live=0, joint_limit=uint64_t{1}<<20;
static int joint_account(int64_t delta) {
    if(delta>0 && uint64_t(delta)>joint_limit-joint_live) return -1;
    if(delta>=0) joint_live+=uint64_t(delta); else joint_live-=uint64_t(-delta);
    return 0;
}
static void joint_budget_checks() {
    C71RangeContext* c=nullptr;
    assert(!c71_range_create(0,262144,256,joint_account,&c));
    const auto owner=stats(c).host_owner_bytes;
    assert(joint_live==owner && !stats(c).arena_bytes);
    joint_limit=owner+256;
    const auto a=alloc(c,C71_U8,17);
    assert(joint_live==owner+256 && stats(c).arena_bytes==256);
    assert(!c71_range_release(c,a));
    assert(joint_live==owner && !stats(c).arena_bytes);
    alloc(c,C71_U8,17);
    const auto before=allocations;
    uint64_t denied=0;
    assert(c71_range_alloc(c,C71_U8,1,&denied));
    assert(!denied && allocations==before && stats(c).stopped);
    close(c);
    assert(joint_live==0);
}
int main() {
    // Original P3 66e2906 Goldilocks generator, including canonical 2^32.
    uint64_t root=0x185629dcda58878cULL;
    for(int bits=32;bits>=0;--bits) {
        assert(c71_pcs::power(7,(P-1)/(uint64_t{1}<<bits))==root);
        root=fp_mul(root,root);
    }
    // Independent signed i128 modulo reference, including every prefix and
    // the 256-product bound used by the resident W kernel.
    uint64_t random=0x53c71a28b79d024fULL;
    for(unsigned test=0;test<2056;++test) {
        c71_pcs::SignedWide dot{};
        __int128 exact=0;
        for(unsigned k=0;k<256;++k) {
            random^=random<<13; random^=random>>7; random^=random<<17;
            int16_t weight=int16_t(int(random%65535)-32767);
            uint64_t factor=random>=P ? random-P : random;
            if(test<8) {
                const int16_t edges[]={-32767,32767,0,1,-1,32767,-32767,1};
                weight=edges[test];
                factor=(test==0 || test==1) ? P-1 : (k%3 ? P-1 : 0);
                if(test>=5 && k%2) weight=int16_t(-weight);
            }
            dot.add(weight,factor);
            exact+=__int128(weight)*factor;
            __int128 residue=exact%__int128(P);
            if(residue<0) residue+=P;
            assert(dot.residue()==uint64_t(residue));
        }
    }
    C71RangeContext* c=nullptr;
    assert(c71_range_runtime_abi()==4);
    assert(c71_range_create(0,6442451200ULL,256,nullptr,&c) && !c && !allocations);
    assert(c71_range_create(0,512,512,nullptr,&c) && !c && !allocations);
    assert(c71_range_create(1,512,256,nullptr,&c) && c);
    C71RangeStats final{}; assert(c71_range_close(c,&final) && final.cleanup_failed);
    c=create(); const auto a=roots(c); const auto root=alloc(c,C71_PAIR,1024);
    assert(!c71_range_runtime_canopy(c,a,root));
    assert(!c71_range_as_children(c,a));
    const auto before=stats(c);
    Round r{}; r.bits=10;
    Cubic result{}; assert(!c71_range_runtime_coefficients(c,a,&r,&result));
    auto after=stats(c);
    assert(after.live_capacity_bytes==before.live_capacity_bytes && after.allocations==before.allocations+2);
    assert(after.peak_capacity_bytes>=before.live_capacity_bytes+512 && after.d2h_bytes==96);
    for(unsigned i=0;i<10;++i) assert(!c71_range_runtime_child_fold(c,a,{0,1,0}));
    after=stats(c); assert(after.live_capacity_bytes==before.live_capacity_bytes && after.logical_bytes<before.logical_bytes);
    uint64_t limbs[12]; assert(!c71_range_read(c,a,limbs,12));
    assert(!c71_range_release(c,a) && !c71_range_release(c,root));
    after=stats(c); assert(!after.live_capacity_bytes && !after.arena_bytes && frees);
    close(c); assert(allocations==frees);

    // Both source types, append coverage, H and retention, scalar root fencing.
    for(unsigned kind=0;kind<2;++kind) {
        c=create(); const auto input=alloc(c,kind,8); int16_t values[8]{};
        assert(!c71_range_upload(c,input,values,8*(kind+1)));
        const auto pairs=alloc(c,C71_PAIR,2), scalar=alloc(c,C71_PAIR,1);
        assert(!c71_range_roots(c,input,3,{1,0,0},pairs,0));
        assert(!c71_range_roots(c,input,3,{1,0,0},pairs,1));
        assert(!c71_range_runtime_canopy(c,pairs,scalar)); assert(!c71_range_read(c,scalar,limbs,6));
        Group g{}; g.bottom=1; g.width=1; g.tail_bits=1; g.buckets=2;
        const auto buckets=alloc(c,C71_GRAM,8), h=alloc(c,C71_GRAM,4), small=alloc(c,C71_GRAM,1);
        assert(!c71_range_zero(c,buckets)); assert(!c71_range_groups(c,input,&g,buckets));
        assert(!c71_range_runtime_h_sum(c,buckets,h,2)); r.bits=1;
        assert(!c71_range_runtime_h_coefficients(c,h,&r,&result));
        assert(!c71_range_runtime_h_fold(c,h,small,{0,1,0}));
        g.width=0; g.tail_bits=2; const auto children=alloc(c,C71_CHILDREN,4);
        assert(!c71_range_groups(c,input,&g,children));
        assert(!c71_range_runtime_child_fold(c,children,{1,0,0}));
        close(c);
    }
    // Every rejection poisons this owner; no subsequent launch or fallback.
    for(unsigned test=0;test<13;++test) {
        c=create(); auto id=roots(c,0,2); int status=0;
        auto initial_launches=launches;
        switch(test) {
        case 0: status=c71_range_read(c,id,limbs,6); break; // not scalar
        case 1: status=c71_range_runtime_canopy(c,id,id); break;
        case 2: assert(!c71_range_release(c,id)); status=c71_range_release(c,id); break;
        case 3: { auto* other=create(); auto foreign=alloc(other,C71_PAIR,1); status=c71_range_release(c,foreign); close(other); break; }
        case 4: { uint64_t ignored; status=c71_range_alloc(c,C71_PAIR,1ULL<<25,&ignored); break; }
        case 5: { uint64_t ignored; status=c71_range_alloc(c,C71_U8,262144,&ignored); break; }
        case 6: { auto x=alloc(c,C71_I16,1); int16_t bad=INT16_MIN; status=c71_range_upload(c,x,&bad,2); break; }
        case 7: { auto x=alloc(c,C71_PAIR,1); status=c71_range_runtime_canopy(c,x,id); break; }
        case 8: assert(!c71_range_as_children(c,id)); status=c71_range_runtime_child_fold(c,id,{P,0,0}); break;
        case 9: { auto x=alloc(c,C71_PAIR,1); fail_launch=true; status=c71_range_runtime_canopy(c,id,x); fail_launch=false; ++initial_launches; break; }
        case 10: assert(!c71_range_as_children(c,id)); fail_fence=true; limbs[0]=123;
            status=c71_range_read(c,id,limbs,12); fail_fence=false; assert(limbs[0]==123); break;
        case 11: assert(!c71_range_as_children(c,id)); corrupt=true; limbs[0]=123;
            status=c71_range_read(c,id,limbs,12); corrupt=false; assert(limbs[0]==123); break;
        case 12: { auto x=alloc(c,C71_U8,8); status=c71_range_roots(c,x,1,{},id,0); break; }
        }
        assert(status && stats(c).stopped && *c71_range_error(c));
        assert(c71_range_runtime_canopy(c,id,id) && launches==initial_launches);
        close(c);
    }
    c=create(); alloc(c,C71_U8,1); fail_free=true;
    assert(c71_range_close(c,&final) && final.cleanup_failed && final.arena_bytes==256);
    fail_free=false;
    joint_budget_checks();
    dense_checks();
    embedding_checks();
    pointwise_checks();
    byte_checks();
    assert(allocations==frees);
    std::puts("C71_RANGE_OWNER_HOST {\"rejections\":13,\"dense_rejections\":23,\"byte_rejections\":19,\"pointwise_rejections\":14,\"embedding_rejections\":17,\"dense_batches\":2,\"dense_row_views\":1,\"max_arena_bytes\":262144,\"gpu_execution\":false,\"credit\":false}");
}
#endif

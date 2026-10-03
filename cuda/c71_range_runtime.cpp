// Single-thread-owned, explicit-device range workspace. No protocol state.
#include "c71_range_runtime.h"
#include <cuda_runtime_api.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <new>
using namespace c71_range;

extern "C" {
cudaError_t c71_range_launch_roots(cudaStream_t,unsigned,const void*,size_t,unsigned,Fp3,Pair*,size_t);
cudaError_t c71_range_launch_groups(cudaStream_t,unsigned,const void*,size_t,Group,Children*,size_t,Fp3*,size_t);
cudaError_t c71_range_launch_canopy(cudaStream_t,const Pair*,Pair*,size_t);
cudaError_t c71_range_launch_h_sum(cudaStream_t,const Fp3*,Fp3*,unsigned,unsigned);
cudaError_t c71_range_launch_h_fold(cudaStream_t,const Fp3*,Fp3*,unsigned,Fp3);
cudaError_t c71_range_launch_child_fold(cudaStream_t,Children*,size_t,Fp3);
cudaError_t c71_range_launch_coefficients(cudaStream_t,const Children*,size_t,Round,Cubic*);
cudaError_t c71_range_launch_reduce(cudaStream_t,const Cubic*,size_t,Cubic*);
cudaError_t c71_range_launch_h_coefficients(cudaStream_t,const Fp3*,unsigned,Round,Cubic*);
cudaError_t c71_dense_i16_launch(cudaStream_t,const int16_t*,uint64_t,const int16_t*,uint64_t,int64_t*,uint64_t,uint32_t*,c71_dense::Shape);
cudaError_t c71_dense_rne_launch(cudaStream_t,const int64_t*,int16_t*,uint64_t,int32_t,uint32_t*);
cudaError_t c71_dense_pointwise_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,uint64_t,c71_dense::Pointwise,uint32_t*);
cudaError_t c71_byte_scatter_launch(cudaStream_t,const void*,unsigned,uint64_t,uint8_t*,uint64_t,uint32_t*,c71_byte::Tile);
cudaError_t c71_lookup_launch(cudaStream_t,const int16_t*,const int16_t*,int16_t*,int64_t*,uint64_t,uint32_t*);
cudaError_t c71_histogram_seal_launch(cudaStream_t,int64_t*,uint32_t*);
cudaError_t c71_rope_launch(cudaStream_t,const int16_t*,const int32_t*,int64_t*,c71_nonlinear::Rope,uint32_t*);
cudaError_t c71_argmax_select_launch(cudaStream_t,const int16_t*,uint32_t*,unsigned,unsigned,uint32_t*);
cudaError_t c71_argmax_slack_launch(cudaStream_t,const int16_t*,const uint32_t*,int16_t*,unsigned,unsigned,uint32_t*);
cudaError_t c71_rms_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,int64_t*,int16_t*,c71_nonlinear::Rms,uint32_t*);
cudaError_t c71_qk_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
cudaError_t c71_pv_launch(cudaStream_t,const int16_t* const*,const int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
cudaError_t c71_softmax_launch(cudaStream_t,const int16_t*,const int32_t*,int16_t*,int16_t*,int64_t*,int64_t*,int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
}

struct Buffer {
    uint64_t id=0, offset=0, capacity=0, count=0, initialized=0;
    uint32_t kind=0;
    uint64_t flag=0;
    uint64_t visits=0;
};
struct C71RangeContext {
    int device=0;
    cudaStream_t stream=nullptr;
    unsigned char* arena=nullptr;
    int16_t* weights=nullptr;
    uint64_t usable=0;
    Buffer buffers[512]{};
    C71RangeStats stats{};
    const char* error="";
};
namespace {
constexpr uint64_t sizes[]={1,2,48,96,24,96,8,1,8};
constexpr uint64_t caps[]={uint64_t{1}<<31,uint64_t{1}<<27,uint64_t{1}<<24,
                          uint64_t{1}<<24,256*32*32,65536,uint64_t(c71_dense::max_m)*c71_dense::max_n,uint64_t{1}<<31,65535};
std::atomic<uint64_t> next_handle{1};
bool canonical(Fp3 a) { return a.c0<P && a.c1<P && a.c2<P; }
bool power2(uint64_t n) { return n && !(n&(n-1)); }
int fail(C71RangeContext* c,const char* message) {
    if(c && !c->stats.stopped) { c->stats.stopped=1; c->error=message; }
    return -1;
}
int checked(C71RangeContext* c,cudaError_t status) {
    return status==cudaSuccess ? 0 : fail(c,cudaGetErrorString(status));
}
bool ready(C71RangeContext* c) {
    return c && !c->stats.stopped && !checked(c,cudaSetDevice(c->device));
}
Buffer* buffer(C71RangeContext* c,uint64_t id) {
    for(auto& b:c->buffers) if(id && b.id==id) return &b;
    fail(c,"unknown or retired range handle"); return nullptr;
}
template<class T> T* ptr(C71RangeContext* c,const Buffer* b) {
    return reinterpret_cast<T*>(c->arena+b->offset);
}
bool full(const Buffer* b,uint32_t kind) {
    return b && b->kind==kind && b->initialized==b->count;
}
bool original(const Buffer* b) { return b && b->kind<=C71_I16 && b->initialized==b->count; }
int fence(C71RangeContext* c) {
    ++c->stats.fences;
    return checked(c,cudaStreamSynchronize(c->stream));
}
int launched(C71RangeContext* c,cudaError_t e) { ++c->stats.launches; return checked(c,e); }
void recount(C71RangeContext* c) {
    c->stats.live_capacity_bytes=0; c->stats.logical_bytes=0;
    for(const auto& b:c->buffers) if(b.id) {
        c->stats.live_capacity_bytes+=b.capacity;
        c->stats.logical_bytes+=b.count*sizes[b.kind];
    }
    c->stats.peak_capacity_bytes=std::max(c->stats.peak_capacity_bytes,c->stats.live_capacity_bytes);
}
bool valid_round(const Round* r,unsigned max_bits) {
    if(!r || !r->bits || r->bits>max_bits || !canonical(r->lambda) || !canonical(r->prefix_equality)) return false;
    for(unsigned i=0;i<r->bits;++i) if(!canonical(r->point[i])) return false;
    return true;
}
// Download only bounded algebraic outputs, with publication AFTER the fence.
int download(C71RangeContext* c,const Buffer* b,void* out,size_t bytes) {
    uint64_t staged[12]{};
    if(checked(c,cudaMemcpyAsync(staged,ptr<void>(c,b),bytes,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=bytes;
    if(fence(c)) return -1;
    for(size_t i=0;i<bytes/8;++i) if(staged[i]>=P) return fail(c,"noncanonical device output");
    std::memcpy(out,staged,bytes); return 0;
}
}

extern "C" uint32_t c71_range_runtime_abi() { return 3; }
extern "C" int c71_range_abort(C71RangeContext* c) { return fail(c,"native caller aborted"); }
extern "C" const char* c71_range_error(const C71RangeContext* c) { return c?c->error:"null range context"; }
extern "C" int c71_range_stats(const C71RangeContext* c,C71RangeStats* out) {
    if(!c || !out) return -1;
    *out=c->stats; return 0;
}
extern "C" int c71_range_create(int device,uint64_t bytes,uint64_t reserve,C71RangeContext** out) {
    if(!out) return -1;
    *out=nullptr;
    if(device<0 || !bytes || bytes>6442450944ULL || bytes%256 || !reserve || reserve%256 || reserve>=bytes) return -1;
    auto* c=new(std::nothrow) C71RangeContext;
    if(!c) return -1;
    c->device=device; c->usable=bytes-reserve; c->stats.host_owner_bytes=sizeof(*c);
    // On an initialization error return the stopped owner for diagnostics/close.
    *out=c;
    if(checked(c,cudaSetDevice(device)) || checked(c,cudaStreamCreateWithFlags(&c->stream,cudaStreamNonBlocking))) return -1;
    if(checked(c,cudaMalloc(reinterpret_cast<void**>(&c->arena),bytes))) return -1;
    c->stats.arena_bytes=bytes; c->stats.peak_reserved_bytes=bytes; return 0;
}
extern "C" int c71_range_close(C71RangeContext* c,C71RangeStats* out) {
    if(!c || !out) return -1;
    bool error=checked(c,cudaSetDevice(c->device))!=0;
    if(!error) {
        if(c->stream && fence(c)) error=true;
        if(c->weights) {
            if(checked(c,cudaFree(c->weights))) error=true;
            else c->stats.weights_bytes=0;
        }
        if(c->arena) {
            if(checked(c,cudaFree(c->arena))) error=true;
            else { c->stats.arena_bytes=0; c->stats.live_capacity_bytes=0; c->stats.logical_bytes=0; }
        }
        if(c->stream && checked(c,cudaStreamDestroy(c->stream))) error=true;
    }
    c->stats.cleanup_failed=error;
    *out=c->stats; delete c; return error?-1:0;
}
extern "C" int c71_range_alloc(C71RangeContext* c,uint32_t kind,uint64_t count,uint64_t* out) {
    if(!ready(c)) return -1;
    if(!out || kind>C71_HISTOGRAM_PENDING || !count || count>caps[kind]) return fail(c,"range allocation shape");
    const uint64_t capacity=(count*sizes[kind]+255)&~uint64_t{255};
    Buffer* slot=nullptr;
    for(auto& b:c->buffers) if(!b.id) { slot=&b; break; }
    if(!slot || capacity>c->usable) return fail(c,"range arena exhausted");
    // ponytail: first-fit scan of at most 512 descriptors; use a free list only
    // if the resident evaluator actually needs more simultaneous buffers.
    uint64_t offset=0;
    for(;;) {
        if(offset>c->usable-capacity) return fail(c,"range arena exhausted");
        uint64_t next=offset;
        for(const auto& b:c->buffers) if(b.id && offset<b.offset+b.capacity && b.offset<offset+capacity)
            next=std::max(next,b.offset+b.capacity);
        if(next==offset) break;
        offset=next;
    }
    uint64_t id=next_handle.load();
    do { if(id==UINT64_MAX) return fail(c,"range handle exhaustion"); }
    while(!next_handle.compare_exchange_weak(id,id+1));
    *slot={id,offset,capacity,count,0,kind}; *out=id;
    ++c->stats.allocations; recount(c); return 0;
}
extern "C" int c71_range_release(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,id); if(!b) return -1;
    if(b->flag && c71_range_release(c,b->flag)) return -1;
    *b={}; ++c->stats.releases; recount(c);
    // No cudaFree: all prior/future uses are ordered on this owner stream.
    return 0;
}
extern "C" int c71_range_upload(C71RangeContext* c,uint64_t id,const void* input,uint64_t bytes) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,id);
    if(!b || b->kind>C71_I16 || !input || bytes!=b->count*sizes[b->kind]) return fail(c,"range upload shape");
    if(b->kind==C71_I16) for(uint64_t i=0;i<b->count;++i) {
        int16_t value; std::memcpy(&value,static_cast<const unsigned char*>(input)+2*i,2);
        if(value==INT16_MIN) return fail(c,"signed range overflow marker");
    }
    if(checked(c,cudaMemcpyAsync(ptr<void>(c,b),input,bytes,cudaMemcpyHostToDevice,c->stream))) return -1;
    c->stats.h2d_bytes+=bytes;
    if(fence(c)) return -1; // Caller may now refill its host window.
    b->initialized=b->count; return 0;
}
extern "C" int c71_range_zero(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,id);
    if(!b || b->kind!=C71_GRAM) return fail(c,"only Gram accumulators may be zeroed");
    const uint64_t bytes=b->count*sizes[b->kind];
    if(checked(c,cudaMemsetAsync(ptr<void>(c,b),0,bytes,c->stream))) return -1;
    c->stats.zeroed_bytes+=bytes; b->initialized=b->count; return 0;
}
extern "C" int c71_range_roots(C71RangeContext* c,uint64_t in,uint32_t bottom,Fp3 alpha,uint64_t out,uint64_t first) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!original(a) || !b || b->kind!=C71_PAIR || bottom<1 || bottom>11 || !canonical(alpha) ||
       a->count%(uint64_t{1}<<bottom)) return fail(c,"range roots shape");
    const uint64_t n=a->count>>bottom;
    if(first!=b->initialized || first>b->count || n>b->count-first) return fail(c,"range roots coverage");
    if(launched(c,c71_range_launch_roots(c->stream,a->kind,ptr<void>(c,a),a->count,bottom,alpha,ptr<Pair>(c,b)+first,n))) return -1;
    b->initialized+=n; return 0;
}
extern "C" int c71_range_runtime_canopy(C71RangeContext* c,uint64_t in,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!full(a,C71_PAIR) || !b || b->kind!=C71_PAIR || a==b || a->count!=2*b->count || !power2(a->count)) return fail(c,"range canopy shape");
    if(launched(c,c71_range_launch_canopy(c->stream,ptr<Pair>(c,a),ptr<Pair>(c,b),b->count))) return -1;
    b->initialized=b->count; return 0;
}
extern "C" int c71_range_as_children(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,id);
    if(!full(b,C71_PAIR) || b->count<2 || !power2(b->count)) return fail(c,"range child reinterpretation");
    b->kind=C71_CHILDREN; b->count/=2; b->initialized=b->count; recount(c); return 0;
}
extern "C" int c71_range_groups(C71RangeContext* c,uint64_t in,const Group* g,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!original(a) || !b || !g || !group_shared_bytes(*g,1)) return fail(c,"range group shape");
    const uint64_t words=uint64_t{1}<<(g->bottom+g->prefix_bits+g->width), tails=a->count/words;
    if(a->count%words || !group_shared_bytes(*g,tails)) return fail(c,"range group coverage");
    if(g->width==0 ? (b->kind!=C71_CHILDREN || b->count!=(uint64_t{1}<<g->tail_bits) || b->initialized!=g->first_tail) :
       (!full(b,C71_GRAM) || b->count!=uint64_t(g->buckets)*(uint64_t{1}<<(2*g->width)))) return fail(c,"range group output");
    if(launched(c,c71_range_launch_groups(c->stream,a->kind,ptr<void>(c,a),a->count,*g,
         g->width?nullptr:ptr<Children>(c,b),g->width?0:b->count,
         g->width?ptr<Fp3>(c,b):nullptr,g->width?b->count:0))) return -1;
    if(!g->width) b->initialized+=tails;
    return 0;
}
extern "C" int c71_range_runtime_h_sum(C71RangeContext* c,uint64_t in,uint64_t out,uint32_t buckets) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!full(a,C71_GRAM) || !b || b->kind!=C71_GRAM || a==b || !buckets || buckets>256 ||
       b->count>1024 || !power2(b->count) || a->count!=buckets*b->count) return fail(c,"range H sum shape");
    unsigned side=1; while(uint64_t(side)*side<b->count) side*=2;
    if(uint64_t(side)*side!=b->count) return fail(c,"range H square shape");
    if(launched(c,c71_range_launch_h_sum(c->stream,ptr<Fp3>(c,a),ptr<Fp3>(c,b),b->count,buckets))) return -1;
    b->initialized=b->count; return 0;
}
extern "C" int c71_range_runtime_h_fold(C71RangeContext* c,uint64_t in,uint64_t out,Fp3 r) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!full(a,C71_GRAM) || !b || b->kind!=C71_GRAM || a==b || a->count!=4*b->count ||
       a->count>1024 || !canonical(r)) return fail(c,"range H fold shape");
    unsigned half=1; while(uint64_t(half)*half<b->count) half*=2;
    if(uint64_t(half)*half!=b->count) return fail(c,"range H square shape");
    if(launched(c,c71_range_launch_h_fold(c->stream,ptr<Fp3>(c,a),ptr<Fp3>(c,b),half,r))) return -1;
    b->initialized=b->count; return 0;
}
extern "C" int c71_range_runtime_child_fold(C71RangeContext* c,uint64_t in,Fp3 r) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in);
    if(!full(a,C71_CHILDREN) || a->count<2 || !power2(a->count) || !canonical(r)) return fail(c,"range child fold shape");
    if(launched(c,c71_range_launch_child_fold(c->stream,ptr<Children>(c,a),a->count/2,r))) return -1;
    a->count/=2; a->initialized=a->count; recount(c); return 0;
}
extern "C" int c71_range_read(C71RangeContext* c,uint64_t in,uint64_t* out,uint32_t limbs) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in);
    if(!a || !out || a->count!=1 || a->initialized!=1 ||
       !((a->kind==C71_PAIR && limbs==6) || (a->kind==C71_CHILDREN && limbs==12))) return fail(c,"range scalar download shape");
    return download(c,a,out,limbs*8);
}
extern "C" int c71_range_runtime_coefficients(C71RangeContext* c,uint64_t in,const Round* r,Cubic* out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in);
    if(!full(a,C71_CHILDREN) || !out || !valid_round(r,24) || a->count!=(uint64_t{1}<<r->bits)) return fail(c,"range coefficients shape");
    uint64_t n=(a->count/2+255)/256, x=0,y=0;
    if(c71_range_alloc(c,C71_CUBIC,n,&x) || (n>1 && c71_range_alloc(c,C71_CUBIC,(n+255)/256,&y))) return -1;
    if(launched(c,c71_range_launch_coefficients(c->stream,ptr<Children>(c,a),a->count/2,*r,ptr<Cubic>(c,buffer(c,x))))) return -1;
    while(n>1) {
        if(launched(c,c71_range_launch_reduce(c->stream,ptr<Cubic>(c,buffer(c,x)),n,ptr<Cubic>(c,buffer(c,y))))) return -1;
        n=(n+255)/256; std::swap(x,y);
    }
    // Both scratch capacities remain charged through the final fence.
    if(download(c,buffer(c,x),out,sizeof(*out))) return -1;
    if(c71_range_release(c,x) || (y && c71_range_release(c,y))) return -1;
    return 0;
}
extern "C" int c71_range_runtime_h_coefficients(C71RangeContext* c,uint64_t in,const Round* r,Cubic* out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in);
    if(!full(a,C71_GRAM) || !out || !valid_round(r,5) || a->count!=(uint64_t{1}<<(2*r->bits))) return fail(c,"range H coefficients shape");
    uint64_t id=0; if(c71_range_alloc(c,C71_CUBIC,1,&id)) return -1;
    if(launched(c,c71_range_launch_h_coefficients(c->stream,ptr<Fp3>(c,a),1u<<(r->bits-1),*r,ptr<Cubic>(c,buffer(c,id))))) return -1;
    if(download(c,buffer(c,id),out,sizeof(*out))) return -1;
    return c71_range_release(c,id);
}

extern "C" int c71_dense_weights_begin(C71RangeContext* c,uint64_t words) {
    if(!ready(c)) return -1;
    constexpr uint64_t margin=uint64_t{1}<<30;
    if(c->weights || !words || words>61394690560ULL/2) return fail(c,"dense W installation shape or replacement");
    const uint64_t bytes=words*2;
    size_t free=0,total=0;
    if(checked(c,cudaMemGetInfo(&free,&total))) return -1;
    if(free<margin || bytes>free-margin || bytes+c->stats.arena_bytes>80000000000ULL-margin)
        return fail(c,"dense W device margin exhausted");
    if(checked(c,cudaMalloc(reinterpret_cast<void**>(&c->weights),bytes))) return -1;
    c->stats.weights_bytes=bytes;
    c->stats.peak_reserved_bytes=c->stats.arena_bytes+bytes;
    // Recheck after allocation; other device users are outside this owner's
    // control. This is an admission check, not a whole-pipeline peak meter.
    if(checked(c,cudaMemGetInfo(&free,&total))) return -1;
    return free>=margin?0:fail(c,"dense W post-allocation margin exhausted");
}
extern "C" int c71_dense_weights_upload(C71RangeContext* c,uint64_t first,const int16_t* input,uint64_t words) {
    if(!ready(c)) return -1;
    uintptr_t end=0;
    if(!c->weights || c->stats.weights_sealed || !input || !words || words>(uint64_t{1}<<27) ||
       first!=c->stats.weights_loaded_bytes/2 || first>c->stats.weights_bytes/2 ||
       words>c->stats.weights_bytes/2-first || !c71_dense::span(input,words*2,end)) return fail(c,"dense W upload coverage");
    for(uint64_t i=0;i<words;++i) {
        int16_t value; std::memcpy(&value,reinterpret_cast<const unsigned char*>(input)+2*i,2);
        if(value==INT16_MIN) return fail(c,"dense W overflow marker");
    }
    if(checked(c,cudaMemcpyAsync(c->weights+first,input,words*2,cudaMemcpyHostToDevice,c->stream))) return -1;
    c->stats.h2d_bytes+=words*2;
    if(fence(c)) return -1;
    c->stats.weights_loaded_bytes+=words*2; return 0;
}
extern "C" int c71_dense_weights_seal(C71RangeContext* c) {
    if(!ready(c)) return -1;
    if(!c->weights || c->stats.weights_sealed || c->stats.weights_loaded_bytes!=c->stats.weights_bytes)
        return fail(c,"dense W incomplete or already sealed");
    c->stats.weights_sealed=1; return 0;
}
namespace {
int dense_flag(C71RangeContext* c,uint64_t* id) {
    if(c71_range_alloc(c,C71_U8,4,id)) return -1;
    if(checked(c,cudaMemsetAsync(ptr<void>(c,buffer(c,*id)),0,4,c->stream))) return -1;
    c->stats.zeroed_bytes+=4; return 0;
}
int dense_complete(C71RangeContext* c,uint64_t flag,Buffer* output) {
    uint32_t failed=0;
    if(checked(c,cudaMemcpyAsync(&failed,ptr<void>(c,buffer(c,flag)),4,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=4;
    if(fence(c)) return -1;
    if(failed) return fail(c,"dense device arithmetic rejection");
    if(c71_range_release(c,flag)) return -1;
    output->initialized=output->count; return 0;
}
}
extern "C" int c71_dense_product_rows(C71RangeContext* c,uint64_t in,uint64_t first_row,uint64_t offset,c71_dense::Shape s,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    const uint64_t nw=uint64_t(s.n)*s.k;
    if(!full(a,C71_I16) || !b || b->kind!=C71_I64 || b->initialized || !c->stats.weights_sealed ||
       offset>c->stats.weights_bytes/2 || nw>c->stats.weights_bytes/2-offset ||
       !c71_dense::valid(s,a->count,nw,b->count) || a->count%s.k || first_row>a->count/s.k ||
       s.m>a->count/s.k-first_row || b->count!=uint64_t(s.m)*s.n)
        return fail(c,"dense product shape or unsealed W");
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_dense_i16_launch(c->stream,ptr<int16_t>(c,a)+first_row*s.k,uint64_t(s.m)*s.k,c->weights+offset,nw,
                                     ptr<int64_t>(c,b),b->count,ptr<uint32_t>(c,buffer(c,flag)),s))) return -1;
    return dense_complete(c,flag,b);
}
extern "C" int c71_dense_product(C71RangeContext* c,uint64_t in,uint64_t offset,c71_dense::Shape s,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in);
    if(!a || a->count!=uint64_t(s.m)*s.k) return fail(c,"dense whole-input shape");
    return c71_dense_product_rows(c,in,0,offset,s,out);
}
extern "C" int c71_dense_quantize(C71RangeContext* c,uint64_t in,int32_t shift,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!full(a,C71_I64) || !b || b->kind!=C71_I16 || b->initialized || a->count!=b->count)
        return fail(c,"dense RNE shape");
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_dense_rne_launch(c->stream,ptr<int64_t>(c,a),ptr<int16_t>(c,b),a->count,shift,
                                     ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    return dense_complete(c,flag,b);
}
extern "C" int c71_dense_embedding(C71RangeContext* c,uint64_t offset,uint32_t vocabulary,uint32_t columns,
    const uint32_t* tokens,uint32_t rows,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out); uintptr_t end=0;
    const uint64_t words=uint64_t(vocabulary)*columns;
    if(!b || b->kind!=C71_I16 || b->initialized || !c->stats.weights_sealed ||
       !rows || rows>150 || !columns || columns>21504 || !vocabulary || vocabulary>262144 ||
       b->count!=uint64_t(rows)*columns || offset>c->stats.weights_bytes/2 ||
       words>c->stats.weights_bytes/2-offset || reinterpret_cast<uintptr_t>(tokens)%4 ||
       !c71_dense::span(tokens,uint64_t(rows)*4,end)) return fail(c,"embedding shape or unsealed W");
    uint32_t ids[150]; std::memcpy(ids,tokens,rows*4);
    for(uint32_t i=0;i<rows;++i) if(ids[i]>=vocabulary) return fail(c,"embedding token outside vocabulary");
    // IDs and the W span are all checked before submitting any copy. Keep
    // repeated IDs in original token order. One stream orders every row copy.
    for(uint32_t i=0;i<rows;++i) {
        if(checked(c,cudaMemcpyAsync(ptr<int16_t>(c,b)+uint64_t(i)*columns,
            c->weights+offset+uint64_t(ids[i])*columns,columns*2,cudaMemcpyDeviceToDevice,c->stream))) return -1;
        c->stats.d2d_bytes+=columns*2;
    }
    if(fence(c)) return -1;
    b->initialized=b->count; return 0;
}
extern "C" int c71_dense_pointwise(C71RangeContext* c,uint64_t x,uint64_t x_first,uint64_t y,uint64_t y_first,
    c71_dense::Pointwise op,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_I64 || b->initialized || !c71_dense::valid_pointwise(op)) return fail(c,"pointwise output or coefficients");
    const uint64_t handles[]={x,y}, first[]={x_first,y_first};
    const bool used[]={op.multiply || op.a,op.multiply || op.b};
    const int16_t* inputs[]={nullptr,nullptr};
    for(unsigned j=0;j<2;++j) {
        if(!used[j]) {
            if(handles[j] || first[j]) return fail(c,"pointwise zero term must be absent");
            continue;
        }
        auto* a=buffer(c,handles[j]);
        if(!full(a,C71_I16) || first[j]>a->count || b->count>a->count-first[j]) return fail(c,"pointwise original input span");
        inputs[j]=ptr<int16_t>(c,a)+first[j];
    }
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_dense_pointwise_launch(c->stream,inputs[0],inputs[1],ptr<int64_t>(c,b),b->count,op,
                                           ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    return dense_complete(c,flag,b);
}
namespace {
const int16_t* nonlinear_input(C71RangeContext* c,uint64_t id,uint64_t first,uint64_t count) {
    auto* a=buffer(c,id);
    if(!full(a,C71_I16) || first>a->count || count>a->count-first) { fail(c,"nonlinear input span"); return nullptr; }
    return ptr<int16_t>(c,a)+first;
}
const unsigned char* nonlinear_table(C71RangeContext* c,uint64_t id,uint64_t offset,uint64_t bytes,unsigned alignment) {
    auto* t=buffer(c,id);
    if(!full(t,C71_U8) || offset%alignment || offset>t->count || bytes>t->count-offset) { fail(c,"nonlinear table span"); return nullptr; }
    return ptr<unsigned char>(c,t)+offset;
}
Buffer* pending(C71RangeContext* context,uint64_t id,unsigned kind,uint64_t count) {
    auto* output=buffer(context,id);
    if(!output || output->kind!=kind || output->initialized || output->count!=count) {
        fail(context,"numeric output shape"); return nullptr;
    }
    return output;
}
const int16_t* attention_tail(C71RangeContext* context,uint64_t id,c71_nonlinear::Attention shape) {
    auto* input=buffer(context,id);
    const uint64_t columns=uint64_t(shape.groups)*shape.lanes;
    if(!input || input->kind!=C71_I16 || input->count<(shape.old+150)*columns || input->count>450*columns ||
        input->initialized<(shape.old+shape.first+shape.rows)*columns) {
        fail(context,"attention tail prefix incomplete"); return nullptr;
    }
    return ptr<int16_t>(context,input);
}
}
extern "C" int c71_signed_append_at(C71RangeContext* context,uint64_t input,uint64_t first,uint64_t count,uint64_t output,uint64_t output_first) {
    if(!ready(context)) return -1;
    auto* source=buffer(context,input); auto* target=buffer(context,output);
    if(!source || !target || source==target || source->kind!=C71_I16 || target->kind!=C71_I16 || !count ||
        first>source->initialized || count>source->initialized-first || output_first!=target->initialized || count>target->count-target->initialized)
        return fail(context,"signed append span or coverage");
    if(checked(context,cudaMemcpyAsync(ptr<int16_t>(context,target)+target->initialized,ptr<int16_t>(context,source)+first,count*2,cudaMemcpyDeviceToDevice,context->stream))) return -1;
    context->stats.d2d_bytes+=count*2;
    if(fence(context)) return -1;
    target->initialized+=count; return 0;
}
extern "C" int c71_original_read(C71RangeContext* context,uint64_t input,uint32_t kind,uint64_t first,uint64_t count,void* output) {
    if(!ready(context)) return -1;
    auto* source=buffer(context,input); uintptr_t end=0;
    if(!source || (kind!=C71_U8 && kind!=C71_I16 && kind!=C71_I64) || source->kind!=kind ||
        !count || count>268435456/sizes[kind] || first>source->initialized || count>source->initialized-first ||
        reinterpret_cast<uintptr_t>(output)%sizes[kind] || !c71_dense::span(output,count*sizes[kind],end))
        return fail(context,"original read kind, span or capacity");
    if(checked(context,cudaMemcpyAsync(output,ptr<unsigned char>(context,source)+first*sizes[kind],count*sizes[kind],cudaMemcpyDeviceToHost,context->stream))) return -1;
    context->stats.d2h_bytes+=count*sizes[kind];
    return fence(context);
}
extern "C" int c71_dense_rms(C71RangeContext* context,uint64_t input,uint64_t first,uint64_t weight_offset,
    c71_nonlinear::Rms shape,uint64_t product,uint64_t statistic,uint64_t output) {
    if(!ready(context)) return -1;
    if(!c71_nonlinear::valid(shape) || (!shape.weighted && (product || weight_offset))) return fail(context,"RMS geometry or coefficients");
    const uint64_t count=uint64_t(shape.rows)*shape.heads*shape.columns;
    auto* raw=shape.weighted?pending(context,product,C71_I64,count):nullptr;
    auto* sums=pending(context,statistic,C71_I64,uint64_t(shape.rows)*shape.heads);
    auto* rounded=pending(context,output,C71_I16,count);
    const auto* values=nonlinear_input(context,input,first,count);
    if(!sums || !rounded || !values || (shape.weighted && (!raw || raw==sums))) return fail(context,"RMS buffers differ");
    if(shape.weighted && (!context->stats.weights_sealed || weight_offset>context->stats.weights_bytes/2 ||
        shape.columns>context->stats.weights_bytes/2-weight_offset)) return fail(context,"RMS original W span");
    uint64_t flag=0; if(dense_flag(context,&flag)) return -1;
    if(launched(context,c71_rms_launch(context->stream,values,shape.weighted?context->weights+weight_offset:nullptr,
        raw?ptr<int64_t>(context,raw):nullptr,ptr<int64_t>(context,sums),ptr<int16_t>(context,rounded),shape,ptr<uint32_t>(context,buffer(context,flag))))) return -1;
    if(dense_complete(context,flag,rounded)) return -1;
    sums->initialized=sums->count; if(raw) raw->initialized=raw->count; return 0;
}
extern "C" int c71_dense_qk(C71RangeContext* context,uint64_t query,uint64_t first,uint64_t keys,c71_nonlinear::Attention shape,uint64_t output) {
    if(!ready(context)) return -1;
    if(!c71_nonlinear::valid(shape)) return fail(context,"QK geometry");
    auto* target=pending(context,output,C71_I64,uint64_t(shape.rows)*(shape.old+150));
    const auto* left=nonlinear_input(context,query,first,uint64_t(shape.rows)*32*shape.lanes);
    const auto* right=attention_tail(context,keys,shape);
    if(!target || !left || !right) return -1;
    uint64_t flag=0; if(dense_flag(context,&flag)) return -1;
    if(launched(context,c71_qk_launch(context->stream,left,right,ptr<int64_t>(context,target),shape,ptr<uint32_t>(context,buffer(context,flag))))) return -1;
    return dense_complete(context,flag,target);
}
extern "C" int c71_dense_pv(C71RangeContext* context,const uint64_t* probabilities,const uint64_t* first,uint64_t values,
    c71_nonlinear::Attention shape,uint64_t output) {
    if(!ready(context)) return -1;
    uintptr_t end=0;
    if(!c71_nonlinear::valid(shape) || !c71_dense::span(probabilities,256,end) || !c71_dense::span(first,256,end) ||
       reinterpret_cast<uintptr_t>(probabilities)%8 || reinterpret_cast<uintptr_t>(first)%8) return fail(context,"PV geometry or input list");
    auto* target=pending(context,output,C71_I64,uint64_t(shape.rows)*32*shape.lanes);
    const auto* tail=attention_tail(context,values,shape);
    if(!target || !tail) return -1;
    const int16_t* pointers[32]{};
    for(unsigned head=0;head<32;++head) {
        pointers[head]=nonlinear_input(context,probabilities[head],first[head],uint64_t(shape.rows)*(shape.old+150));
        if(!pointers[head]) return -1;
    }
    uint64_t flag=0; if(dense_flag(context,&flag)) return -1;
    if(launched(context,c71_pv_launch(context->stream,pointers,tail,ptr<int64_t>(context,target),shape,ptr<uint32_t>(context,buffer(context,flag))))) return -1;
    return dense_complete(context,flag,target);
}
extern "C" int c71_dense_softmax(C71RangeContext* context,uint64_t input,uint64_t first,uint64_t table,uint64_t table_offset,
    uint64_t histogram,c71_nonlinear::Attention shape,const uint64_t* outputs) {
    if(!ready(context)) return -1;
    uintptr_t end=0;
    if(!c71_nonlinear::valid(shape) || !c71_dense::span(outputs,40,end) || reinterpret_cast<uintptr_t>(outputs)%8)
        return fail(context,"softmax geometry or outputs");
    const uint64_t count=uint64_t(shape.rows)*(shape.old+150);
    const unsigned kinds[]={C71_I16,C71_I16,C71_I64,C71_I64,C71_I16};
    Buffer* targets[5]{};
    for(unsigned index=0;index<5;++index) {
        targets[index]=pending(context,outputs[index],kinds[index],index==0 || index==3?shape.rows:count);
        if(!targets[index]) return -1;
        for(unsigned previous=0;previous<index;++previous) if(targets[index]==targets[previous]) return fail(context,"softmax outputs alias");
    }
    auto* counts=buffer(context,histogram);
    if(!full(counts,C71_HISTOGRAM_PENDING) || counts->count!=65535 || count>uint64_t(INT32_MAX)-counts->visits) return fail(context,"softmax histogram shape");
    const auto* scores=nonlinear_input(context,input,first,count);
    const auto* lookup=nonlinear_table(context,table,table_offset,65535*4,4);
    if(!scores || !lookup) return -1;
    uint64_t flag=0; if(dense_flag(context,&flag)) return -1;
    if(launched(context,c71_softmax_launch(context->stream,scores,reinterpret_cast<const int32_t*>(lookup),
        ptr<int16_t>(context,targets[0]),ptr<int16_t>(context,targets[1]),ptr<int64_t>(context,targets[2]),
        ptr<int64_t>(context,targets[3]),ptr<int16_t>(context,targets[4]),ptr<int64_t>(context,counts),shape,ptr<uint32_t>(context,buffer(context,flag))))) return -1;
    if(dense_complete(context,flag,targets[0])) return -1;
    for(auto* target:targets) target->initialized=target->count;
    counts->visits+=count; return 0;
}
extern "C" int c71_histogram_padding(C71RangeContext* context,uint64_t histogram,uint64_t count) {
    if(!ready(context)) return -1;
    auto* target=buffer(context,histogram);
    if(!full(target,C71_HISTOGRAM_PENDING) || target->count!=65535 || target->visits || !count || count>INT32_MAX)
        return fail(context,"histogram padding coverage");
    if(checked(context,cudaMemcpyAsync(ptr<void>(context,target),&count,8,cudaMemcpyHostToDevice,context->stream))) return -1;
    context->stats.h2d_bytes+=8;
    if(fence(context)) return -1;
    target->visits=count; return 0;
}
extern "C" int c71_histogram_begin(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* h=buffer(c,id);
    if(!h || h->kind!=C71_HISTOGRAM_PENDING || h->initialized || h->count!=65535) return fail(c,"histogram initialization shape");
    if(checked(c,cudaMemsetAsync(ptr<void>(c,h),0,h->count*8,c->stream))) return -1;
    c->stats.zeroed_bytes+=h->count*8; h->initialized=h->count; return 0;
}
extern "C" int c71_histogram_seal(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* h=buffer(c,id);
    if(!full(h,C71_HISTOGRAM_PENDING) || h->count!=65535) return fail(c,"histogram seal shape");
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_histogram_seal_launch(c->stream,ptr<int64_t>(c,h),ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    if(dense_complete(c,flag,h)) return -1;
    h->kind=C71_I64; return 0;
}
extern "C" int c71_dense_lookup(C71RangeContext* c,uint64_t in,uint64_t first,uint64_t table,uint64_t offset,uint64_t hist,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out); auto* h=buffer(c,hist);
    if(!b || b->kind!=C71_I16 || b->initialized || b->count>uint64_t(c71_dense::max_m)*c71_dense::max_n ||
       !full(h,C71_HISTOGRAM_PENDING) || h->count!=65535 || b->count>uint64_t(INT32_MAX)-h->visits) return fail(c,"lookup output or histogram shape");
    const auto* x=nonlinear_input(c,in,first,b->count);
    const auto* t=nonlinear_table(c,table,offset,65535*2,2);
    if(!x || !t) return -1;
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_lookup_launch(c->stream,x,reinterpret_cast<const int16_t*>(t),ptr<int16_t>(c,b),ptr<int64_t>(c,h),b->count,ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    if(dense_complete(c,flag,b)) return -1;
    h->visits+=b->count; return 0;
}
extern "C" int c71_dense_rope(C71RangeContext* c,uint64_t in,uint64_t first,uint64_t table,uint64_t offset,c71_nonlinear::Rope s,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    const uint64_t count=uint64_t(s.rows)*s.heads*s.width;
    if(!b || b->kind!=C71_I64 || b->initialized || !c71_nonlinear::valid(s) || b->count!=count) return fail(c,"RoPE output shape");
    const auto* x=nonlinear_input(c,in,first,count);
    const auto* t=nonlinear_table(c,table,offset,uint64_t(s.rows)*s.pairs*8,4);
    if(!x || !t) return -1;
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_rope_launch(c->stream,x,reinterpret_cast<const int32_t*>(t),ptr<int64_t>(c,b),s,ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    return dense_complete(c,flag,b);
}
extern "C" int c71_dense_argmax(C71RangeContext* c,uint64_t in,uint64_t first,uint32_t rows,uint32_t columns,uint64_t out,uint32_t* public_tokens) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out); uintptr_t end=0;
    if(!rows || rows>150 || !columns || columns>262144 || !b || b->kind!=C71_I16 || b->initialized ||
       b->count!=uint64_t(rows)*columns || reinterpret_cast<uintptr_t>(public_tokens)%4 ||
       !c71_dense::span(public_tokens,rows*4,end)) return fail(c,"argmax output shape");
    const auto* x=nonlinear_input(c,in,first,b->count); if(!x) return -1;
    uint64_t flag=0,tokens=0;
    if(dense_flag(c,&flag) || c71_range_alloc(c,C71_U8,rows*4,&tokens)) return -1;
    auto* t=buffer(c,tokens); auto* f=buffer(c,flag);
    if(launched(c,c71_argmax_select_launch(c->stream,x,ptr<uint32_t>(c,t),rows,columns,ptr<uint32_t>(c,f))) ||
       launched(c,c71_argmax_slack_launch(c->stream,x,ptr<uint32_t>(c,t),ptr<int16_t>(c,b),rows,columns,ptr<uint32_t>(c,f)))) return -1;
    if(dense_complete(c,flag,b)) return -1;
    uint32_t staged[150]{};
    if(checked(c,cudaMemcpyAsync(staged,ptr<void>(c,t),rows*4,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=rows*4;
    if(fence(c)) return -1;
    for(unsigned i=0;i<rows;++i) if(staged[i]>=columns) return fail(c,"argmax token outside vocabulary");
    if(c71_range_release(c,tokens)) return -1;
    b->initialized=b->count; std::memcpy(public_tokens,staged,rows*4); return 0;
}
extern "C" int c71_byte_begin(C71RangeContext* c,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_BYTE_PENDING || b->initialized || b->flag) return fail(c,"byte window already begun or wrong kind");
    if(dense_flag(c,&b->flag)) return -1;
    if(checked(c,cudaMemsetAsync(ptr<void>(c,b),0,b->count,c->stream))) return -1;
    c->stats.zeroed_bytes+=b->count; return 0;
}
extern "C" int c71_byte_scatter(C71RangeContext* c,uint64_t in,const c71_byte::Tile* t,uint64_t out) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!a || !a->initialized || !b || b->kind!=C71_BYTE_PENDING || !b->flag || !t ||
       !c71_byte::valid(*t,a->kind,a->initialized,b->count)) return fail(c,"byte scatter source or window shape");
    return launched(c,c71_byte_scatter_launch(c->stream,ptr<void>(c,a),a->kind,a->initialized,ptr<uint8_t>(c,b),b->count,
                                              ptr<uint32_t>(c,buffer(c,b->flag)),*t));
}
extern "C" int c71_byte_seal(C71RangeContext* c,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_BYTE_PENDING || !b->flag) return fail(c,"byte seal requires pending window");
    if(dense_complete(c,b->flag,b)) return -1;
    b->flag=0; b->kind=C71_U8; return 0;
}

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
}

struct Buffer {
    uint64_t id=0, offset=0, capacity=0, count=0, initialized=0;
    uint32_t kind=0;
};
struct C71RangeContext {
    int device=0;
    cudaStream_t stream=nullptr;
    unsigned char* arena=nullptr;
    int16_t* weights=nullptr;
    uint64_t usable=0;
    Buffer buffers[64]{};
    C71RangeStats stats{};
    const char* error="";
};
namespace {
constexpr uint64_t sizes[]={1,2,48,96,24,96,8};
constexpr uint64_t caps[]={uint64_t{1}<<31,uint64_t{1}<<27,uint64_t{1}<<24,
                          uint64_t{1}<<24,256*32*32,65536,uint64_t(c71_dense::max_m)*c71_dense::max_n};
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

extern "C" uint32_t c71_range_runtime_abi() { return 2; }
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
    if(!out || kind>C71_I64 || !count || count>caps[kind]) return fail(c,"range allocation shape");
    const uint64_t capacity=(count*sizes[kind]+255)&~uint64_t{255};
    Buffer* slot=nullptr;
    for(auto& b:c->buffers) if(!b.id) { slot=&b; break; }
    if(!slot || capacity>c->usable) return fail(c,"range arena exhausted");
    // ponytail: first-fit scan of at most 64 descriptors; use a free list only
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

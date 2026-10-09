// Single-thread-owned common workspace; private PCS state is consumer-bound.
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
cudaError_t c71_pcs_hash_launch(cudaStream_t,unsigned,const uint64_t*,const uint64_t*,c71_pcs::Hash32*,uint64_t,uint64_t,uint64_t,unsigned,uint32_t*);
cudaError_t c71_pcs_nodes_launch(cudaStream_t,const c71_pcs::Hash32*,c71_pcs::Hash32*,uint64_t,uint64_t);
cudaError_t c71_pcs_merge_launch(cudaStream_t,c71_pcs::Hash32*,c71_pcs::Hash32*,uint64_t,unsigned,unsigned);
cudaError_t c71_pcs_powers_launch(cudaStream_t,uint64_t*,uint64_t*,c71_pcs::WeightShape);
cudaError_t c71_pcs_weight_launch(cudaStream_t,const int16_t*,const c71_pcs::WeightTile*,uint64_t,uint64_t,
    const uint64_t*,const uint64_t*,const uint64_t*,uint64_t*,c71_pcs::WeightShape,uint32_t*);
cudaError_t c71_pcs_weight_tensor_launch(cudaStream_t,const int16_t*,const c71_pcs::WeightTile*,uint64_t,uint64_t,
    const uint64_t*,const uint64_t*,const uint64_t*,uint64_t*,c71_pcs::WeightShape,uint32_t*);
cudaError_t c71_pcs_compare_words_launch(cudaStream_t,const uint64_t*,const uint64_t*,uint64_t,uint32_t*);
cudaError_t c71_pcs_fft_launch(cudaStream_t,uint64_t*,const uint64_t*,unsigned,unsigned,unsigned*);
cudaError_t c71_pcs_twiddles_launch(cudaStream_t,uint64_t*,unsigned);
cudaError_t c71_pcs_transform_twiddles_launch(cudaStream_t,uint64_t*,unsigned,unsigned);
cudaError_t c71_pcs_transform_launch(cudaStream_t,uint64_t*,uint64_t*,const uint64_t*,unsigned,unsigned,unsigned,unsigned*);
cudaError_t c71_pcs_query_low_launch(cudaStream_t,const uint8_t*,const uint64_t*,uint64_t*,uint64_t,c71_pcs::QueryBlock);
cudaError_t c71_pcs_query_remainder_launch(cudaStream_t,const uint64_t*,const uint64_t*,const uint64_t*,const uint64_t*,
    const uint64_t*,const uint64_t*,uint64_t*,uint64_t*,uint64_t*,uint64_t,uint64_t,unsigned,unsigned*,uint64_t*);
cudaError_t c71_pcs_query_shift_launch(cudaStream_t,const uint64_t*,const uint64_t*,const uint64_t*,const uint64_t*,
    uint64_t*,uint64_t*,uint64_t*,uint64_t*,uint64_t,unsigned*,uint64_t*);
cudaError_t c71_pcs_query_add_launch(cudaStream_t,uint64_t*,const uint64_t*,uint64_t);
cudaError_t c71_linear_weights_launch(cudaStream_t,const int16_t*,const c71_pcs::WeightTile*,uint64_t,uint64_t,uint64_t,
    c71_linear::Shape,const c71_linear::Chunk*,const Fp3*,const c71_linear::Group*,const c71_linear::Interval*,
    const Fp3*,c71_linear::Result*,uint32_t*);
cudaError_t c71_linear_source_launch(cudaStream_t,const void*,unsigned,c71_pcs::SourceTile,c71_linear::Shape,
    const c71_linear::Chunk*,const Fp3*,const c71_linear::Group*,const c71_linear::Interval*,
    const Fp3*,c71_linear::Result*,uint32_t*);
cudaError_t c71_pcs_source_powers_launch(cudaStream_t,uint64_t*,uint64_t*,c71_pcs::SourceShape);
cudaError_t c71_pcs_source_tile_launch(cudaStream_t,const void*,unsigned,c71_pcs::SourceTile,const uint64_t*,
    uint64_t*,uint64_t*,uint64_t*,c71_pcs::SourceShape,uint32_t*);
cudaError_t c71_pcs_source_pad_launch(cudaStream_t,uint64_t*,const uint64_t*,const uint64_t*,const uint64_t*,
    c71_pcs::SourceShape,unsigned,uint32_t*);
cudaError_t c71_pcs_full_leaves_launch(cudaStream_t,const uint64_t*,const uint64_t*,const uint64_t*,
    c71_pcs::Hash32*,uint64_t,uint64_t,uint64_t,uint32_t*);
cudaError_t c71_pcs_salts_prescan_launch(cudaStream_t,const c71_salts::Descriptor*,c71_salts::Chunk,c71_salts::Geometry,
    uint8_t*,uint32_t*,uint32_t*,uint32_t*,uint64_t*,uint64_t*,c71_salts::Progress*,uint32_t*,unsigned*);
cudaError_t c71_pcs_salts_replay_launch(cudaStream_t,const c71_salts::Descriptor*,uint64_t*,uint64_t,uint64_t,uint64_t,
    uint64_t*,uint64_t*,uint32_t*);
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
    uint64_t id=0;
    void* allocation=nullptr;
    uint64_t capacity=0, count=0, initialized=0;
    uint32_t kind=0;
    uint64_t flag=0;
    uint64_t visits=0;
    bool release_failed=false;
};
struct LinearTransaction {
    c71_linear::Shape shape{};
    uint64_t meta=0,output=0,flag=0,offsets[6]{},visited=0;
    uint32_t phase=0,mode=0;
};
static_assert(sizeof(LinearTransaction)==120);
struct C71RangeContext {
    C71RangeAccount account=nullptr;
    int device=0;
    cudaStream_t stream=nullptr;
    int16_t* weights=nullptr;
    uint64_t usable=0;
    Buffer buffers[512]{};
    C71RangeStats stats{};
    const char* error="";
    // At most one pending source reconstruction on this owner. Numeric
    // producers borrow their original buffers; this record contains no coins.
    struct {
        c71_pcs::SourceShape shape{};
        uint64_t values[2]{}, low=0, high=0, histogram=0, bytes=0;
    } source;
    // Proof consumer only; no private pointer/token reaches a numeric source.
    struct {
        c71_salts::Geometry geometry{};
        c71_salts::Chunk chunk{};
        uint64_t meta=0,scratch=0,current=0,offsets=0,band=0,end=0,completed_bytes=0;
        uint32_t group_cosets=0,group=0,phase=0;
        uint64_t first=0;
    } salts;
    LinearTransaction linear{};
};
namespace {
constexpr uint64_t sizes[]={1,2,48,96,24,96,8,1,8,8,32,32,32,40,8,8,8,1,1};
constexpr uint64_t caps[]={uint64_t{1}<<31,uint64_t{1}<<27,uint64_t{1}<<24,
                          uint64_t{1}<<24,256*32*32,65536,uint64_t(c71_dense::max_m)*c71_dense::max_n,uint64_t{1}<<31,65535,
                          uint64_t{1}<<28,uint64_t{1}<<25,uint64_t{1}<<25,uint64_t{1}<<25,65536,uint64_t{1}<<25,
                          uint64_t{1}<<28,256,uint64_t{1}<<28,uint64_t{1}<<30};
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
    (void)c;
    return static_cast<T*>(b->allocation);
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
    c->stats.arena_bytes=c->stats.live_capacity_bytes;
    c->stats.peak_reserved_bytes=std::max(c->stats.peak_reserved_bytes,
        c->stats.arena_bytes+c->stats.weights_bytes);
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

extern "C" uint32_t c71_range_runtime_abi() { return 4; }
extern "C" int c71_range_abort(C71RangeContext* c) { return fail(c,"native caller aborted"); }
extern "C" const char* c71_range_error(const C71RangeContext* c) { return c?c->error:"null range context"; }
extern "C" int c71_range_stats(const C71RangeContext* c,C71RangeStats* out) {
    if(!c || !out) return -1;
    *out=c->stats; return 0;
}
extern "C" int c71_range_create(int device,uint64_t bytes,uint64_t reserve,C71RangeAccount account,C71RangeContext** out) {
    if(!out) return -1;
    *out=nullptr;
    if(device<0 || !bytes || bytes>6442450944ULL || bytes%256 || !reserve || reserve%256 || reserve>=bytes) return -1;
    if(account && account(sizeof(C71RangeContext))) return -1;
    auto* c=new(std::nothrow) C71RangeContext;
    if(!c) { if(account) account(-int64_t(sizeof(C71RangeContext))); return -1; }
    c->account=account;
    c->device=device; c->usable=bytes-reserve; c->stats.host_owner_bytes=sizeof(*c);
    // On an initialization error return the stopped owner for diagnostics/close.
    *out=c;
    if(checked(c,cudaSetDevice(device)) || checked(c,cudaStreamCreateWithFlags(&c->stream,cudaStreamNonBlocking))) return -1;
    return 0; // Budget only: idle device capacity must not coexist with host PCS.
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
        for(auto& b:c->buffers) if(b.id) {
            // A failed cudaFree has uncertain ownership. Never submit the same
            // pointer again; keep its entire capacity in the failure ledger.
            if(b.release_failed || checked(c,cudaFree(b.allocation))) error=true;
            else { if(c->account) c->account(-int64_t(b.capacity)); b={}; }
        }
        recount(c);
        if(c->stream && checked(c,cudaStreamDestroy(c->stream))) error=true;
    }
    c->stats.cleanup_failed=error;
    *out=c->stats;
    if(c->account) c->account(-int64_t(sizeof(*c)));
    delete c; return error?-1:0;
}
namespace {
int allocate(C71RangeContext* c,uint32_t kind,uint64_t count,uint64_t* out) {
    if(!ready(c)) return -1;
    if(!out || kind>C71_LINEAR_PRIVATE || !count || count>caps[kind]) return fail(c,"range allocation shape");
    const uint64_t capacity=(count*sizes[kind]+255)&~uint64_t{255};
    Buffer* slot=nullptr;
    for(auto& b:c->buffers) if(!b.id) { slot=&b; break; }
    if(!slot || capacity>c->usable || c->stats.arena_bytes>c->usable-capacity)
        return fail(c,"range arena exhausted");
    uint64_t id=next_handle.load();
    do { if(id==UINT64_MAX) return fail(c,"range handle exhaustion"); }
    while(!next_handle.compare_exchange_weak(id,id+1));
    void* allocation=nullptr;
    if(c->account && c->account(int64_t(capacity))) return fail(c,"joint temporary budget exhausted");
    if(checked(c,cudaMalloc(&allocation,capacity))) {
        if(c->account) c->account(-int64_t(capacity));
        return -1;
    }
    *slot={id,allocation,capacity,count,0,kind}; *out=id;
    ++c->stats.allocations; recount(c); return 0;
}
}
extern "C" int c71_range_alloc(C71RangeContext* c,uint32_t kind,uint64_t count,uint64_t* out) {
    if(kind>C71_PCS_BYTE_COUNTS_PENDING) return fail(c,"private allocation requires PCS capability");
    return allocate(c,kind,count,out);
}
extern "C" int c71_range_release(C71RangeContext* c,uint64_t id) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,id); if(!b) return -1;
    if(b->kind>=C71_PCS_PRIVATE) return fail(c,"private release requires consumer capability");
    if(b->flag && c71_range_release(c,b->flag)) return -1;
    // Actual release, not a logical Vec-style truncation or a retained pool.
    // Fence even on the deferred test driver; a failure keeps capacity charged.
    if(fence(c)) return -1;
    if(checked(c,cudaFree(b->allocation))) { b->release_failed=true; return -1; }
    if(c->account) c->account(-int64_t(b->capacity));
    *b={}; ++c->stats.releases; recount(c);
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
    c->stats.peak_reserved_bytes=std::max(c->stats.peak_reserved_bytes,c->stats.arena_bytes+bytes);
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
    // This stream has already completed every use of its internal flag. No
    // operation is queued before the free; the public release remains fenced.
    auto* completed_flag=buffer(c,flag);
    if(checked(c,cudaFree(completed_flag->allocation))) { completed_flag->release_failed=true; return -1; }
    if(c->account) c->account(-int64_t(completed_flag->capacity));
    *completed_flag={}; ++c->stats.releases; recount(c);
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

extern "C" int c71_pcs_words_upload(C71RangeContext* c,uint64_t out,uint64_t first,const uint64_t* words,uint64_t count) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_PCS_BASE || !words || !count || count>(uint64_t{1}<<25) ||
       first>b->count || count>b->count-first || (b->initialized!=b->count && first!=b->initialized))
        return fail(c,"PCS upload shape or coverage");
    for(uint64_t i=0;i<count;++i) if(words[i]>=P) return fail(c,"PCS noncanonical base word");
    if(checked(c,cudaMemcpyAsync(ptr<uint64_t>(c,b)+first,words,count*8,cudaMemcpyHostToDevice,c->stream))) return -1;
    c->stats.h2d_bytes+=count*8;
    if(fence(c)) return -1;
    if(b->initialized!=b->count) b->initialized+=count;
    return 0;
}
extern "C" int c71_pcs_leaf_start(C71RangeContext* c,uint64_t ring,uint64_t states) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,ring); auto* b=buffer(c,states);
    if(!full(a,C71_PCS_BASE) || !b || b->kind!=C71_PCS_HASH_PENDING || b->initialized || b->flag ||
       a->count!=8*b->count) return fail(c,"PCS leaf start shape or state");
    if(dense_flag(c,&b->flag)) return -1;
    if(launched(c,c71_pcs_hash_launch(c->stream,0,ptr<uint64_t>(c,a),nullptr,
        ptr<c71_pcs::Hash32>(c,b),b->count,0,b->count,0,ptr<uint32_t>(c,buffer(c,b->flag))))) return -1;
    b->initialized=b->count; b->visits=4; return 0;
}
extern "C" int c71_pcs_leaf_step(C71RangeContext* c,uint64_t ring,uint64_t states,uint32_t first) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,ring); auto* b=buffer(c,states);
    if(!full(a,C71_PCS_BASE) || !full(b,C71_PCS_HASH_PENDING) || !b->flag ||
       a->count!=8*b->count || first!=b->visits || first>116)
        return fail(c,"PCS leaf step shape or order");
    if(launched(c,c71_pcs_hash_launch(c->stream,1,ptr<uint64_t>(c,a),nullptr,
        ptr<c71_pcs::Hash32>(c,b),b->count,0,b->count,first,ptr<uint32_t>(c,buffer(c,b->flag))))) return -1;
    b->visits+=8; return 0;
}
extern "C" int c71_pcs_leaf_finish(C71RangeContext* c,uint64_t ring,uint64_t salts,uint64_t states,uint64_t first,uint64_t count) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,ring); auto* s=buffer(c,salts); auto* b=buffer(c,states);
    if(!full(a,C71_PCS_BASE) || !full(s,C71_PCS_BASE) || !full(b,C71_PCS_HASH_PENDING) || !b->flag ||
       a->count!=8*b->count || !count || first>b->count || count>b->count-first ||
       s->count!=4*count || b->visits!=124+first)
        return fail(c,"PCS leaf finish shape or incomplete state");
    if(launched(c,c71_pcs_hash_launch(c->stream,2,ptr<uint64_t>(c,a),ptr<uint64_t>(c,s),
        ptr<c71_pcs::Hash32>(c,b),b->count,first,count,124,ptr<uint32_t>(c,buffer(c,b->flag))))) return -1;
    b->visits+=count;
    if(first+count!=b->count) return 0;
    if(dense_complete(c,b->flag,b)) return -1;
    b->flag=0; b->kind=C71_PCS_DIGEST; return 0;
}
extern "C" int c71_pcs_nodes(C71RangeContext* c,uint64_t in,uint64_t out,uint64_t rows) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,out);
    if(!full(a,C71_PCS_DIGEST) || !b || b->kind!=C71_PCS_DIGEST || b->initialized ||
       !rows || b->count%rows || a->count!=2*b->count) return fail(c,"PCS Merkle shape or digest type");
    if(launched(c,c71_pcs_nodes_launch(c->stream,ptr<c71_pcs::Hash32>(c,a),ptr<c71_pcs::Hash32>(c,b),b->count,rows))) return -1;
    b->initialized=b->count; return 0;
}
extern "C" int c71_pcs_read_digests(C71RangeContext* c,uint64_t in,uint64_t first,uint64_t count,void* out) {
    if(!ready(c)) return -1;
    if(c->salts.phase) return fail(c,"PCS salts must complete before digest publication");
    auto* a=buffer(c,in);
    if(!full(a,C71_PCS_DIGEST) || !out || !count || count>(uint64_t{1}<<21) ||
       first>a->count || count>a->count-first) return fail(c,"PCS digest publication shape or state");
    if(checked(c,cudaMemcpyAsync(out,ptr<c71_pcs::Hash32>(c,a)+first,count*32,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=count*32;
    return fence(c);
}
extern "C" int c71_pcs_frontier_begin(C71RangeContext* c,uint64_t out,uint64_t rows,uint32_t groups) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_PCS_FRONTIER_PENDING || b->initialized || !power2(rows) ||
       !power2(groups) || groups<2 || groups>4096) return fail(c,"PCS frontier geometry or state");
    unsigned levels=0; while((1u<<levels)<groups) ++levels;
    if(rows>(uint64_t{1}<<25)/levels || b->count!=rows*levels) return fail(c,"PCS frontier capacity");
    // initialized stores row geometry, not full validity: this kind has no
    // reader. visits packs immutable levels and the next consecutive group.
    b->initialized=rows; b->visits=uint64_t(levels)<<32; return 0;
}
extern "C" int c71_pcs_merge_group(C71RangeContext* c,uint64_t in,uint64_t roots,uint32_t group) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,in); auto* b=buffer(c,roots);
    if(!a || a->kind!=C71_PCS_FRONTIER_PENDING || !a->initialized || !full(b,C71_PCS_DIGEST) ||
       b->count!=a->initialized || group!=uint32_t(a->visits) || group>=(1u<<(a->visits>>32)))
        return fail(c,"PCS frontier group order, shape or type");
    if(launched(c,c71_pcs_merge_launch(c->stream,ptr<c71_pcs::Hash32>(c,a),ptr<c71_pcs::Hash32>(c,b),
        b->count,group,unsigned(a->visits>>32)))) return -1;
    ++a->visits; return 0;
}
extern "C" int c71_pcs_tiles_upload(C71RangeContext* c,uint64_t out,const c71_pcs::WeightTile* tiles,uint64_t count) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!c->stats.weights_sealed || !b || b->kind!=C71_PCS_WEIGHT_TILES || b->initialized ||
       !tiles || count!=b->count) return fail(c,"PCS W tiles shape or replacement");
    const uint64_t live=c->stats.weights_bytes/2;
    uint64_t covered=0;
    for(uint64_t i=0;i<count;++i) {
        const auto t=tiles[i];
        if(t.first!=covered || !power2(t.count) || !power2(t.columns) || t.columns>t.count ||
           t.count>live-covered || t.packed_stride<t.columns || t.packed_first>live ||
           t.columns>live-t.packed_first || t.count/t.columns-1>(live-t.packed_first-t.columns)/t.packed_stride)
            return fail(c,"PCS W tile coverage or packed span");
        covered+=t.count;
    }
    if(covered!=live) return fail(c,"PCS W tiles incomplete");
    if(checked(c,cudaMemcpyAsync(ptr<void>(c,b),tiles,count*sizeof(*tiles),cudaMemcpyHostToDevice,c->stream))) return -1;
    c->stats.h2d_bytes+=count*sizeof(*tiles);
    if(fence(c)) return -1;
    b->initialized=count; b->visits=live; return 0;
}
extern "C" int c71_pcs_powers(C71RangeContext* c,uint64_t low,uint64_t high,c71_pcs::WeightShape s) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,low); auto* b=buffer(c,high);
    if(!c71_pcs::valid(s) || !a || !b || a==b || a->kind!=C71_PCS_POWERS || b->kind!=C71_PCS_POWERS ||
       a->initialized || b->initialized || a->count!=32*s.rows || b->count!=32*c71_pcs::high_rows(s))
        return fail(c,"PCS coset power geometry or state");
    if(launched(c,c71_pcs_powers_launch(c->stream,ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),s))) return -1;
    a->initialized=a->count; b->initialized=b->count;
    a->visits=b->visits=(uint64_t(s.cosets)<<32)|s.first_coset; return 0;
}
extern "C" int c71_pcs_twiddles(C71RangeContext* c,uint64_t out,uint32_t log_rows) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_PCS_POWERS || b->initialized || log_rows<2 || log_rows>20 || log_rows%2 ||
       b->count!=(uint64_t{1}<<log_rows)) return fail(c,"PCS FFT twiddle geometry or state");
    if(launched(c,c71_pcs_twiddles_launch(c->stream,ptr<uint64_t>(c,b),log_rows))) return -1;
    b->initialized=b->count; b->visits=(uint64_t{1}<<63)|b->count; return 0;
}
extern "C" int c71_pcs_transform_twiddles(C71RangeContext* c,uint64_t out,uint32_t log_rows,uint32_t inverse) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_PCS_POWERS || b->initialized || log_rows<1 || log_rows>24 || inverse>1 ||
       b->count!=(uint64_t{1}<<log_rows)) return fail(c,"PCS transform twiddle geometry or state");
    if(launched(c,c71_pcs_transform_twiddles_launch(c->stream,ptr<uint64_t>(c,b),log_rows,inverse))) return -1;
    b->initialized=b->count; b->visits=(uint64_t{1}<<63)|(uint64_t(inverse)<<62)|b->count; return 0;
}
extern "C" int c71_pcs_transform(C71RangeContext* c,uint64_t values,uint64_t scratch,uint64_t twiddles,
    uint32_t log_rows,uint32_t batch,uint32_t inverse) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,values); auto* s=buffer(c,scratch); auto* t=buffer(c,twiddles);
    if(!full(b,C71_PCS_BASE) || !s || s->kind!=C71_PCS_BASE || !full(t,C71_PCS_POWERS) ||
       b==s || b==t || s==t || log_rows<1 || log_rows>24 || inverse>1 || !batch || batch>(1u<<20) ||
       b->count!=(uint64_t{1}<<log_rows)*batch || s->count!=b->count || t->count!=(uint64_t{1}<<log_rows) ||
       t->visits!=((uint64_t{1}<<63)|(uint64_t(inverse)<<62)|t->count))
        return fail(c,"PCS natural transform type, geometry or orientation");
    unsigned attempted=0;
    const auto status=c71_pcs_transform_launch(c->stream,ptr<uint64_t>(c,b),ptr<uint64_t>(c,s),
        ptr<uint64_t>(c,t),log_rows,batch,inverse,&attempted);
    c->stats.launches+=attempted;
    // Reaching the FFT launch means the odd scatter's D2D copy was queued.
    if(log_rows%2 && log_rows>1 && attempted>1) c->stats.d2d_bytes+=b->count*8;
    if(checked(c,status)) return -1;
    if(log_rows%2 && log_rows>1) s->initialized=s->count;
    return 0; // The consuming operation or download fences the same stream.
}
extern "C" int c71_pcs_read_words(C71RangeContext* c,uint64_t input,uint64_t first,uint64_t count,uint64_t* output) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,input); uintptr_t end=0;
    if(!full(b,C71_PCS_BASE) || c->salts.phase || !output || !count || count>(uint64_t{1}<<20) ||
       first>b->count || count>b->count-first || reinterpret_cast<uintptr_t>(output)%8 ||
       !c71_dense::span(output,count*8,end)) return fail(c,"PCS base read shape, type or private phase");
    if(checked(c,cudaMemcpyAsync(output,ptr<uint64_t>(c,b)+first,count*8,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=count*8;
    if(fence(c)) return -1;
    for(uint64_t i=0;i<count;++i) if(output[i]>=P) return fail(c,"noncanonical PCS base output");
    return 0;
}
namespace {
bool query_twiddles(const Buffer* b,uint64_t count,unsigned inverse) {
    return full(b,C71_PCS_POWERS) && b->count==count &&
        b->visits==((uint64_t{1}<<63)|(uint64_t(inverse)<<62)|count);
}
bool query_output(const Buffer* b,uint64_t count) {
    return b && b->kind==C71_PCS_BASE && b->count==count;
}
}
extern "C" int c71_pcs_query_low(C71RangeContext* c,uint64_t bytes,uint64_t pads,uint64_t low,c71_pcs::QueryBlock s) {
    if(!ready(c)) return -1;
    auto* b=bytes?buffer(c,bytes):nullptr; auto* p=buffer(c,pads); auto* l=buffer(c,low);
    if(bytes && !b) return -1;
    if(!l || l->kind!=C71_PCS_BASE || !power2(l->count) || l->count>(uint64_t{1}<<20) ||
       !full(p,C71_PCS_BASE) || p==l || (b && (!full(b,C71_U8) || b->count>(uint64_t{1}<<28))) ||
       s.pad_only>1 || !power2(s.message_rows) ||
       s.message_rows>(uint64_t{1}<<27) || s.active>s.message_rows || !s.pad_rows || s.pad_rows>1536 ||
       s.pad_first>p->count || s.pad_rows>p->count-s.pad_first || s.first%l->count ||
       s.first>(uint64_t{1}<<28) || s.byte_first>(uint64_t{1}<<35) ||
       (s.pad_only ? (s.active || s.source_rows!=s.pad_rows) :
           (s.source_rows!=s.active && s.source_rows!=s.message_rows+s.pad_rows)))
        return fail(c,"PCS query low geometry, pads or type");
    const uint64_t end=std::min(s.active,s.first+l->count);
    if(!s.pad_only && end>s.first) {
        if(!full(b,C71_U8) || b->count>(uint64_t{1}<<28) || s.window_first>s.byte_first+s.first ||
           s.byte_first+end-s.window_first>b->count) return fail(c,"PCS query original byte window coverage");
    }
    if(launched(c,c71_pcs_query_low_launch(c->stream,b?ptr<uint8_t>(c,b):nullptr,
        ptr<uint64_t>(c,p),ptr<uint64_t>(c,l),l->count,s))) return -1;
    l->initialized=l->count; return 0;
}
extern "C" int c71_pcs_query_remainder(C71RangeContext* c,uint64_t high,uint64_t low,uint64_t inverse,uint64_t modulus,
    uint64_t forward,uint64_t backward,uint64_t work,uint64_t scratch,uint64_t output,uint64_t degree,uint32_t children) {
    if(!ready(c)) return -1;
    auto* h=buffer(c,high); auto* l=buffer(c,low); auto* i=buffer(c,inverse); auto* m=buffer(c,modulus);
    auto* f=buffer(c,forward); auto* b=buffer(c,backward); auto* w=buffer(c,work); auto* s=buffer(c,scratch); auto* o=buffer(c,output);
    if(!o || !power2(o->count) || o->count>(uint64_t{1}<<20) || !power2(degree) || degree>o->count || children>1 ||
       (children ? (degree==o->count || h!=l) : degree!=o->count) ||
       !full(h,C71_PCS_BASE) || !full(l,C71_PCS_BASE) || h->count!=o->count || l->count!=o->count ||
       !full(i,C71_PCS_BASE) || !full(m,C71_PCS_BASE) || i==m || i->count!=2*o->count || m->count!=2*o->count ||
       !query_twiddles(f,2*degree,0) || !query_twiddles(b,2*degree,1) ||
       !query_output(w,2*o->count) || !query_output(s,2*o->count) || !query_output(o,o->count) || w==s || w==o || s==o)
        return fail(c,"PCS query remainder type, degree or factor geometry");
    for(auto* read:{h,l,i,m,f,b}) if(read==w || read==s || read==o)
        return fail(c,"PCS query remainder output alias");
    unsigned attempted=0; uint64_t copied=0;
    const auto status=c71_pcs_query_remainder_launch(c->stream,ptr<uint64_t>(c,h),ptr<uint64_t>(c,l),
        ptr<uint64_t>(c,i),ptr<uint64_t>(c,m),ptr<uint64_t>(c,f),ptr<uint64_t>(c,b),ptr<uint64_t>(c,w),
        ptr<uint64_t>(c,s),ptr<uint64_t>(c,o),degree,o->count,children,&attempted,&copied);
    c->stats.launches+=attempted; c->stats.d2d_bytes+=copied;
    if(checked(c,status)) return -1;
    o->initialized=o->count; return 0; // final bounded read fences the same stream
}
extern "C" int c71_pcs_query_shift(C71RangeContext* c,uint64_t values,uint64_t shift,uint64_t forward,uint64_t backward,
    uint64_t work,uint64_t scratch,uint64_t low,uint64_t high) {
    if(!ready(c)) return -1;
    auto* v=buffer(c,values); auto* t=buffer(c,shift); auto* f=buffer(c,forward); auto* b=buffer(c,backward);
    auto* w=buffer(c,work); auto* s=buffer(c,scratch); auto* l=buffer(c,low); auto* h=buffer(c,high);
    if(!full(v,C71_PCS_BASE) || !power2(v->count) || v->count>(uint64_t{1}<<20) ||
       !full(t,C71_PCS_BASE) || t->count!=2*v->count || !query_twiddles(f,2*v->count,0) ||
       !query_twiddles(b,2*v->count,1) || !query_output(w,2*v->count) || !query_output(s,2*v->count) ||
       !query_output(l,v->count) || !query_output(h,v->count) || w==s || l==h || w==l || w==h || s==l || s==h)
        return fail(c,"PCS query pad shift geometry or workspace alias");
    for(auto* read:{v,t,f,b}) if(read==w || read==s || (read!=v && (read==l || read==h)))
        return fail(c,"PCS query pad shift input alias");
    unsigned attempted=0; uint64_t copied=0;
    const auto status=c71_pcs_query_shift_launch(c->stream,ptr<uint64_t>(c,v),ptr<uint64_t>(c,t),
        ptr<uint64_t>(c,f),ptr<uint64_t>(c,b),ptr<uint64_t>(c,w),ptr<uint64_t>(c,s),ptr<uint64_t>(c,l),
        ptr<uint64_t>(c,h),v->count,&attempted,&copied);
    c->stats.launches+=attempted; c->stats.d2d_bytes+=copied;
    if(checked(c,status)) return -1;
    l->initialized=l->count; h->initialized=h->count; return 0;
}
extern "C" int c71_pcs_query_add(C71RangeContext* c,uint64_t values,uint64_t correction) {
    if(!ready(c)) return -1;
    auto* v=buffer(c,values); auto* a=buffer(c,correction);
    if(!full(v,C71_PCS_BASE) || !full(a,C71_PCS_BASE) || v==a || v->count!=a->count || v->count>(uint64_t{1}<<20))
        return fail(c,"PCS query correction geometry or alias");
    return launched(c,c71_pcs_query_add_launch(c->stream,ptr<uint64_t>(c,v),ptr<uint64_t>(c,a),v->count));
}
extern "C" int c71_pcs_ring_zero(C71RangeContext* c,uint64_t out) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,out);
    if(!b || b->kind!=C71_PCS_BASE || b->initialized) return fail(c,"PCS ring initialization state");
    if(checked(c,cudaMemsetAsync(ptr<void>(c,b),0,b->count*8,c->stream))) return -1;
    c->stats.zeroed_bytes+=b->count*8; b->initialized=b->count; return 0;
}
namespace {
int pcs_weight(C71RangeContext* c,uint64_t tiles,uint64_t pads,uint64_t low,
    uint64_t high,uint64_t twiddles,uint64_t ring,c71_pcs::WeightShape s,bool tensor) {
    if(!ready(c)) return -1;
    auto* t=buffer(c,tiles); auto* p=buffer(c,pads); auto* a=buffer(c,low);
    auto* b=buffer(c,high); auto* w=buffer(c,twiddles); auto* out=buffer(c,ring);
    const uint64_t binding=(uint64_t(s.cosets)<<32)|s.first_coset;
    if(!c71_pcs::valid(s) || a==b || p==out || !c->stats.weights_sealed || !full(t,C71_PCS_WEIGHT_TILES) ||
       t->visits!=c->stats.weights_bytes/2 || t->visits>128*s.message_rows ||
       !full(p,C71_PCS_BASE) || p->count!=128*s.pad_rows || !full(a,C71_PCS_POWERS) || a->count!=32*s.rows ||
       !full(b,C71_PCS_POWERS) || b->count!=32*c71_pcs::high_rows(s) || a->visits!=binding || b->visits!=binding ||
       !full(w,C71_PCS_POWERS) || w->count!=s.rows || w->visits!=((uint64_t{1}<<63)|s.rows) ||
       !full(out,C71_PCS_BASE) || out->count!=8*32*s.rows) return fail(c,"PCS resident W inputs or geometry");
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    const auto accumulate=tensor?c71_pcs_weight_tensor_launch:c71_pcs_weight_launch;
    if(launched(c,accumulate(c->stream,c->weights,ptr<c71_pcs::WeightTile>(c,t),t->count,t->visits,
        ptr<uint64_t>(c,p),ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),ptr<uint64_t>(c,out),s,ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    unsigned log_rows=0; while((uint64_t{1}<<log_rows)<s.rows) ++log_rows;
    unsigned attempted=0;
    const auto error=c71_pcs_fft_launch(c->stream,ptr<uint64_t>(c,out)+s.slots*32*s.rows,
        ptr<uint64_t>(c,w),log_rows,4*32,&attempted);
    c->stats.launches+=attempted;
    if(checked(c,error)) return -1;
    return dense_complete(c,flag,out);
}
}
extern "C" int c71_pcs_weight(C71RangeContext* c,uint64_t tiles,uint64_t pads,uint64_t low,
    uint64_t high,uint64_t twiddles,uint64_t ring,c71_pcs::WeightShape s) {
    return pcs_weight(c,tiles,pads,low,high,twiddles,ring,s,false);
}
extern "C" int c71_pcs_weight_tensor(C71RangeContext* c,uint64_t tiles,uint64_t pads,uint64_t low,
    uint64_t high,uint64_t twiddles,uint64_t ring,c71_pcs::WeightShape s) {
    return pcs_weight(c,tiles,pads,low,high,twiddles,ring,s,true);
}
extern "C" int c71_pcs_compare_words(C71RangeContext* c,uint64_t left,uint64_t right) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,left); auto* b=buffer(c,right);
    if(a==b || !full(a,C71_PCS_BASE) || !full(b,C71_PCS_BASE) || a->count!=b->count)
        return fail(c,"PCS word comparison type, coverage, count or alias");
    uint64_t flag=0; if(dense_flag(c,&flag)) return -1;
    if(launched(c,c71_pcs_compare_words_launch(c->stream,ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),a->count,
        ptr<uint32_t>(c,buffer(c,flag))))) return -1;
    return dense_complete(c,flag,a); // a is already full; its words stay read-only
}

extern "C" int c71_pcs_source_powers(C71RangeContext* c,uint64_t low,uint64_t high,c71_pcs::SourceShape s) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,low); auto* b=buffer(c,high);
    if(!c71_pcs::valid(s) || !a || !b || a==b || a->kind!=C71_PCS_POWERS || b->kind!=C71_PCS_POWERS ||
       a->initialized || b->initialized || a->count!=4*s.rows || b->count!=4*c71_pcs::high_rows(s))
        return fail(c,"PCS source coset powers or state");
    if(launched(c,c71_pcs_source_powers_launch(c->stream,ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),s))) return -1;
    a->initialized=a->count; b->initialized=b->count;
    a->visits=b->visits=(uint64_t(s.cosets)<<32)|s.first_coset; return 0;
}
extern "C" int c71_pcs_source_begin(C71RangeContext* c,uint64_t first,uint64_t second,uint64_t low,
    uint64_t high,uint64_t histogram,c71_pcs::SourceShape s) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,first); auto* b=buffer(c,second);
    auto* l=buffer(c,low); auto* h=buffer(c,high);
    auto* counts=histogram?buffer(c,histogram):nullptr;
    const uint64_t binding=(uint64_t(s.cosets)<<32)|s.first_coset;
    if(!c71_pcs::valid(s) || c->source.values[0] || c->linear.phase || !a || !b || a==b || a->flag || b->flag ||
       a->kind!=C71_PCS_SOURCE_PENDING || b->kind!=C71_PCS_SOURCE_PENDING || a->initialized || b->initialized ||
       a->count!=256*s.rows || b->count!=a->count || l==h || !full(l,C71_PCS_POWERS) || !full(h,C71_PCS_POWERS) ||
       l->count!=4*s.rows || h->count!=4*c71_pcs::high_rows(s) || l->visits!=binding || h->visits!=binding ||
       (histogram && (!counts || counts->kind!=C71_PCS_BYTE_COUNTS_PENDING || counts->initialized || counts->count!=256 || s.first_coset)))
        return fail(c,"PCS source begin geometry, powers or state");
    if(dense_flag(c,&a->flag)) return -1;
    for(auto* out: {a,b,counts}) if(out) {
        if(checked(c,cudaMemsetAsync(ptr<void>(c,out),0,out->count*8,c->stream))) return -1;
        c->stats.zeroed_bytes+=out->count*8;
    }
    c->source={s,{first,second},low,high,histogram,0}; return 0;
}
extern "C" int c71_pcs_source_tile(C71RangeContext* c,uint64_t original,const c71_pcs::SourceTile* tile) {
    if(!ready(c)) return -1;
    auto* input=buffer(c,original);
    const auto s=c->source.shape;
    if(!c->source.values[0] || !input || (input->kind!=C71_I16 && input->kind!=C71_I64) || input->initialized!=input->count ||
       !tile || !c71_pcs::valid(*tile,input->kind,input->count,s.live)) return fail(c,"PCS original source tile or state");
    const uint64_t bytes=tile->rows*tile->columns*tile->width;
    if(bytes>s.live-c->source.bytes) return fail(c,"PCS source byte coverage exceeds live prefix");
    auto* a=buffer(c,c->source.values[0]); auto* b=buffer(c,c->source.values[1]);
    auto* high=buffer(c,c->source.high); auto* counts=c->source.histogram?buffer(c,c->source.histogram):nullptr;
    if(!a || !b || a->kind!=C71_PCS_SOURCE_PENDING || b->kind!=C71_PCS_SOURCE_PENDING || !a->flag ||
       !full(high,C71_PCS_POWERS) || (c->source.histogram && !counts)) return fail(c,"PCS source inputs retired or published");
    if(launched(c,c71_pcs_source_tile_launch(c->stream,ptr<void>(c,input),input->kind,*tile,
        ptr<uint64_t>(c,high),ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),counts?ptr<uint64_t>(c,counts):nullptr,s,
        ptr<uint32_t>(c,buffer(c,a->flag))))) return -1;
    c->source.bytes+=bytes; return 0;
}
extern "C" int c71_pcs_source_finish(C71RangeContext* c,uint64_t first,uint64_t second,uint64_t histogram,uint64_t pads,uint64_t twiddles) {
    if(!ready(c)) return -1;
    const auto s=c->source.shape;
    if(!c->source.values[0] || c->source.bytes!=s.live || first!=c->source.values[0] || second!=c->source.values[1] ||
       histogram!=c->source.histogram) return fail(c,"PCS original source coverage or output binding differs");
    auto* a=buffer(c,c->source.values[0]); auto* b=buffer(c,c->source.values[1]);
    auto* l=buffer(c,c->source.low); auto* h=buffer(c,c->source.high);
    auto* p=buffer(c,pads); auto* w=buffer(c,twiddles);
    auto* counts=c->source.histogram?buffer(c,c->source.histogram):nullptr;
    if(!a || !b || a->kind!=C71_PCS_SOURCE_PENDING || b->kind!=C71_PCS_SOURCE_PENDING || !a->flag || p==a || p==b ||
       !full(l,C71_PCS_POWERS) || !full(h,C71_PCS_POWERS) || !full(p,C71_PCS_BASE) || p->count!=128*s.pad_rows ||
       !full(w,C71_PCS_POWERS) || w->count!=s.rows || w->visits!=((uint64_t{1}<<63)|s.rows) ||
       (c->source.histogram && (!counts || counts->kind!=C71_PCS_BYTE_COUNTS_PENDING))) return fail(c,"PCS source final inputs or state");
    unsigned log_rows=0; while((uint64_t{1}<<log_rows)<s.rows) ++log_rows;
    for(unsigned half=0;half<2;++half) {
        auto* out=half?b:a;
        if(launched(c,c71_pcs_source_pad_launch(c->stream,ptr<uint64_t>(c,out),ptr<uint64_t>(c,p),ptr<uint64_t>(c,l),
            ptr<uint64_t>(c,h),s,64*half,ptr<uint32_t>(c,buffer(c,a->flag))))) return -1;
        unsigned attempted=0;
        const auto error=c71_pcs_fft_launch(c->stream,ptr<uint64_t>(c,out),ptr<uint64_t>(c,w),log_rows,256,&attempted);
        c->stats.launches+=attempted;
        if(checked(c,error)) return -1;
    }
    if(dense_complete(c,a->flag,a)) return -1;
    a->flag=0; a->kind=b->kind=C71_PCS_BASE; b->initialized=b->count;
    if(counts) { counts->kind=C71_I64; counts->initialized=counts->count; }
    c->source={}; return 0;
}
extern "C" int c71_pcs_full_leaves(C71RangeContext* c,uint64_t first,uint64_t second,uint64_t salts,
    uint64_t output,uint64_t begin,uint64_t count) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,first); auto* b=buffer(c,second); auto* s=buffer(c,salts); auto* out=buffer(c,output);
    if(!full(a,C71_PCS_BASE) || !full(b,C71_PCS_BASE) || a==b || !full(s,C71_PCS_BASE) || !out ||
       out->kind!=C71_PCS_HASH_PENDING || !count || begin>out->count || count>out->count-begin ||
       a->count!=64*out->count || b->count!=a->count || s->count!=4*count || begin!=out->visits ||
       (begin==0 ? (out->flag || out->initialized) : (!out->flag || out->initialized!=begin)))
        return fail(c,"PCS full leaf geometry, state or salt coverage");
    if(!begin && dense_flag(c,&out->flag)) return -1;
    if(launched(c,c71_pcs_full_leaves_launch(c->stream,ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),ptr<uint64_t>(c,s),
        ptr<c71_pcs::Hash32>(c,out),out->count,begin,count,ptr<uint32_t>(c,buffer(c,out->flag))))) return -1;
    out->initialized+=count; out->visits+=count;
    if(begin+count!=out->count) return 0;
    if(dense_complete(c,out->flag,out)) return -1;
    out->flag=0; out->kind=C71_PCS_DIGEST; return 0;
}

namespace {
struct PrivateMeta {
    c71_salts::Descriptor descriptor;
    c71_salts::Progress progress{};
    uint32_t failed=0;
    uint64_t consumed=0;
};
static_assert(sizeof(PrivateMeta)==168);
uint64_t aligned(uint64_t n) { return (n+255)&~uint64_t{255}; }
struct SaltScratch {
    uint64_t prefix,blocks,groups,bytes;
    explicit SaltScratch(uint32_t capacity) {
        const uint64_t n=uint64_t(capacity)/8+1;
        prefix=aligned(n); blocks=prefix+aligned(4*n);
        groups=blocks+aligned(4*((n+255)/256));
        bytes=groups+aligned(4*((n+65535)/65536));
    }
};
PrivateMeta* private_meta(C71RangeContext* c) {
    return ptr<PrivateMeta>(c,buffer(c,c->salts.meta));
}
bool private_session(C71RangeContext* c,uint64_t session,uint32_t phase) {
    if(!session || session!=c->salts.meta || c->salts.phase!=phase) {
        fail(c,"private PCS capability or phase differs"); return false;
    }
    return true;
}
// Every caller has already fenced all uses. A failed free retains capacity
// and ownership uncertainty, just as the common owner's other releases.
int retire_private(C71RangeContext* c,uint64_t& id) {
    if(!id) return 0;
    auto* b=buffer(c,id);
    if(!b || b->kind!=C71_PCS_PRIVATE) return fail(c,"private PCS retirement type");
    if(checked(c,cudaFree(b->allocation))) { b->release_failed=true; return -1; }
    if(c->account) c->account(-int64_t(b->capacity));
    *b={}; id=0; ++c->stats.releases; recount(c); return 0;
}
bool private_band(C71RangeContext* c,uint64_t session,uint32_t group,uint64_t first,uint64_t count) {
    const uint64_t rows=c->salts.geometry.rows*c->salts.group_cosets;
    if(!private_session(c,session,3) || group!=c->salts.group || first!=c->salts.first ||
       !count || count!=std::min(uint64_t{65536},rows) || first>rows || count>rows-first) {
        fail(c,"private PCS group or band coverage"); return false;
    }
    return true;
}
int private_replay(C71RangeContext* c,Buffer* out,uint64_t first,uint64_t count) {
    auto* m=private_meta(c);
    return launched(c,c71_pcs_salts_replay_launch(c->stream,&m->descriptor,
        ptr<uint64_t>(c,buffer(c,c->salts.current)),c->salts.geometry.rows,first,count,
        ptr<uint64_t>(c,buffer(c,c->salts.band)),&m->consumed,ptr<uint32_t>(c,buffer(c,out->flag))));
}
int private_hash_complete(C71RangeContext* c,Buffer* out,uint64_t count,uint64_t* completed) {
    c->salts.first+=count;
    if(c->salts.first!=out->count) { *completed=c->salts.completed_bytes; return 0; }
    uint64_t consumed=0;
    if(checked(c,cudaMemcpyAsync(&consumed,&private_meta(c)->consumed,8,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=8;
    if(dense_complete(c,out->flag,out)) return -1;
    const uint64_t total=c->salts.end-c->salts.geometry.origin;
    const uint64_t minimum=uint64_t(c->salts.group+1)*out->count*32;
    const bool last=c->salts.group+1==c->salts.geometry.cosets/c->salts.group_cosets;
    if(consumed<=c->salts.completed_bytes || consumed<minimum || consumed>total || (last && consumed!=total))
        return fail(c,"private PCS replay consumption differs");
    out->flag=0; out->kind=C71_PCS_DIGEST;
    c->salts.completed_bytes=consumed; ++c->salts.group; c->salts.first=0;
    if(last) c->salts.phase=4;
    *completed=consumed; return 0;
}
}

extern "C" int c71_pcs_salts_begin(C71RangeContext* c,const uint8_t seed[32],c71_salts::Geometry g,
    uint32_t group_cosets,uint32_t capacity,uint64_t* session) {
    if(!ready(c)) return -1;
    if(session) *session=0;
    if(!session || !seed || c->salts.phase || c->linear.phase || !c71_salts::valid(g) || g.cut<g.cosets ||
       (group_cosets!=4 && group_cosets!=32) || group_cosets>g.cosets || !c71_salts::valid_capacity(capacity))
        return fail(c,"private PCS seed or geometry");
    auto& s=c->salts;
    s.phase=1; s.geometry=g; s.group_cosets=group_cosets;
    s.chunk={g.origin,0,4*g.rows*g.cosets,0,capacity};
    const SaltScratch layout(capacity);
    if(allocate(c,C71_PCS_PRIVATE,sizeof(PrivateMeta),&s.meta) ||
       allocate(c,C71_PCS_PRIVATE,layout.bytes,&s.scratch) ||
       allocate(c,C71_PCS_PRIVATE,8*g.rows,&s.current) ||
       allocate(c,C71_PCS_PRIVATE,8*g.rows*g.cosets/g.cut,&s.offsets)) return -1;
    const PrivateMeta initial{c71_salts::descriptor(seed)};
    if(checked(c,cudaMemcpyAsync(private_meta(c),&initial,sizeof(initial),cudaMemcpyHostToDevice,c->stream))) return -1;
    c->stats.h2d_bytes+=sizeof(initial);
    if(fence(c)) return -1;
    *session=s.meta; return 0;
}

extern "C" int c71_pcs_salts_prescan(C71RangeContext* c,uint64_t session,c71_salts::Progress* output) {
    if(!ready(c)) return -1;
    if(!output || !private_session(c,session,1)) return fail(c,"private PCS prescan output or phase");
    auto& s=c->salts;
    s.chunk.candidates=uint32_t(std::min({uint64_t(s.chunk.capacity),s.chunk.target-s.chunk.accepted,
        (c71_salts::CAP-s.chunk.cursor)/8}));
    const auto chunk=s.chunk; const SaltScratch layout(chunk.capacity);
    auto* scratch=ptr<uint8_t>(c,buffer(c,s.scratch)); auto* m=private_meta(c);
    unsigned attempted=0;
    const auto status=c71_pcs_salts_prescan_launch(c->stream,&m->descriptor,chunk,s.geometry,
        scratch,reinterpret_cast<uint32_t*>(scratch+layout.prefix),reinterpret_cast<uint32_t*>(scratch+layout.blocks),
        reinterpret_cast<uint32_t*>(scratch+layout.groups),ptr<uint64_t>(c,buffer(c,s.current)),
        ptr<uint64_t>(c,buffer(c,s.offsets)),&m->progress,&m->failed,&attempted);
    c->stats.launches+=attempted; if(checked(c,status)) return -1;
    struct { c71_salts::Progress progress; uint32_t failed; } staged{};
    if(checked(c,cudaMemcpyAsync(&staged,&m->progress,sizeof(c71_salts::Progress)+4,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=sizeof(c71_salts::Progress)+4;
    if(fence(c)) return -1;
    const auto& p=staged.progress;
    if(staged.failed || p.failed || p.complete>1 || p.cursor<chunk.cursor || p.cursor>c71_salts::CAP ||
       p.cursor-chunk.cursor>8*uint64_t(chunk.candidates) || (p.cursor-s.geometry.origin)%8 ||
       p.accepted<chunk.accepted || p.accepted>chunk.target || p.accepted-chunk.accepted>chunk.candidates ||
       p.logical_bytes!=p.cursor-s.geometry.origin || p.physical_blocks!=c71_salts::physical_blocks(chunk) ||
       p.complete!=(p.accepted==chunk.target) || (!p.complete && p.cursor!=chunk.cursor+8*uint64_t(chunk.candidates)))
        return fail(c,"private PCS prescan rejection or inconsistent progress");
    s.chunk.cursor=p.cursor; s.chunk.accepted=p.accepted;
    if(p.complete) { s.end=p.cursor; s.phase=2; }
    *output=p; return 0;
}

extern "C" int c71_pcs_salts_indices(C71RangeContext* c,uint64_t session,uint64_t* starts,uint64_t rows,
    uint64_t* offsets,uint64_t count) {
    if(!ready(c)) return -1;
    uintptr_t starts_end=0,offsets_end=0;
    if(!private_session(c,session,2) || !starts || !offsets || starts==offsets ||
       rows!=c->salts.geometry.rows || count!=rows*c->salts.geometry.cosets/c->salts.geometry.cut ||
       !c71_dense::span(starts,8*rows,starts_end) || !c71_dense::span(offsets,8*count,offsets_end) ||
       reinterpret_cast<uintptr_t>(starts)%8 || reinterpret_cast<uintptr_t>(offsets)%8 ||
       (reinterpret_cast<uintptr_t>(starts)<offsets_end && reinterpret_cast<uintptr_t>(offsets)<starts_end))
        return fail(c,"private PCS indices shape or alias");
    if(checked(c,cudaMemcpyAsync(starts,ptr<void>(c,buffer(c,c->salts.current)),8*rows,cudaMemcpyDeviceToHost,c->stream)) ||
       checked(c,cudaMemcpyAsync(offsets,ptr<void>(c,buffer(c,c->salts.offsets)),8*count,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=8*(rows+count);
    if(fence(c)) return -1;
    if(starts[0]!=c->salts.geometry.origin || offsets[0]!=starts[0]) return fail(c,"private PCS indices origin differs");
    for(uint64_t i=0;i<rows;++i) if(starts[i]>=c->salts.end || (i && starts[i]<=starts[i-1]))
        return fail(c,"private PCS row offsets differ");
    for(uint64_t i=0;i<count;++i) if(offsets[i]>=c->salts.end || (i && offsets[i]<=offsets[i-1]))
        return fail(c,"private PCS subtree offsets differ");
    if(retire_private(c,c->salts.scratch) || retire_private(c,c->salts.offsets)) return -1;
    if(allocate(c,C71_PCS_PRIVATE,32*std::min(uint64_t{65536},rows*c->salts.group_cosets),&c->salts.band)) return -1;
    c->salts.phase=3; return 0;
}

extern "C" int c71_pcs_leaf_finish_private(C71RangeContext* c,uint64_t session,uint64_t ring,uint64_t states,
    uint32_t group,uint64_t first,uint64_t count,uint64_t* completed) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,ring); auto* b=buffer(c,states);
    if(!completed || !private_band(c,session,group,first,count) || c->salts.group_cosets!=32 ||
       !full(a,C71_PCS_BASE) || !full(b,C71_PCS_HASH_PENDING) || !b->flag ||
       b->count!=32*c->salts.geometry.rows || a->count!=8*b->count || b->visits!=124+first)
        return fail(c,"private PCS W leaf state or coverage");
    if(private_replay(c,b,first,count) || launched(c,c71_pcs_hash_launch(c->stream,2,ptr<uint64_t>(c,a),
        ptr<uint64_t>(c,buffer(c,c->salts.band)),ptr<c71_pcs::Hash32>(c,b),b->count,first,count,124,
        ptr<uint32_t>(c,buffer(c,b->flag))))) return -1;
    b->visits+=count; return private_hash_complete(c,b,count,completed);
}

extern "C" int c71_pcs_full_leaves_private(C71RangeContext* c,uint64_t session,uint64_t first_values,uint64_t second_values,
    uint64_t states,uint32_t group,uint64_t first,uint64_t count,uint64_t* completed) {
    if(!ready(c)) return -1;
    auto* a=buffer(c,first_values); auto* b=buffer(c,second_values); auto* out=buffer(c,states);
    if(!completed || !private_band(c,session,group,first,count) || c->salts.group_cosets!=4 ||
       !full(a,C71_PCS_BASE) || !full(b,C71_PCS_BASE) || a==b || !out || out->kind!=C71_PCS_HASH_PENDING ||
       out->count!=4*c->salts.geometry.rows || a->count!=64*out->count || b->count!=a->count || first!=out->visits ||
       (first==0 ? (out->flag || out->initialized) : (!out->flag || out->initialized!=first)))
        return fail(c,"private PCS A leaf state or coverage");
    if(!first && dense_flag(c,&out->flag)) return -1;
    if(private_replay(c,out,first,count) || launched(c,c71_pcs_full_leaves_launch(c->stream,ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),
        ptr<uint64_t>(c,buffer(c,c->salts.band)),ptr<c71_pcs::Hash32>(c,out),out->count,first,count,
        ptr<uint32_t>(c,buffer(c,out->flag))))) return -1;
    out->initialized+=count; out->visits+=count;
    return private_hash_complete(c,out,count,completed);
}

extern "C" int c71_pcs_salts_complete(C71RangeContext* c,uint64_t session,uint64_t* current,uint64_t rows,uint64_t* consumed) {
    if(!ready(c)) return -1;
    uintptr_t current_end=0,consumed_end=0;
    if(!private_session(c,session,4) || !current || !consumed || rows!=c->salts.geometry.rows ||
       c->salts.completed_bytes!=c->salts.end-c->salts.geometry.origin ||
       !c71_dense::span(current,8*rows,current_end) || !c71_dense::span(consumed,8,consumed_end) ||
       reinterpret_cast<uintptr_t>(current)%8 || reinterpret_cast<uintptr_t>(consumed)%8 ||
       (reinterpret_cast<uintptr_t>(current)<consumed_end && reinterpret_cast<uintptr_t>(consumed)<current_end))
        return fail(c,"private PCS replay final coverage");
    if(checked(c,cudaMemcpyAsync(current,ptr<void>(c,buffer(c,c->salts.current)),8*rows,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=8*rows;
    if(fence(c)) return -1;
    if(current[rows-1]!=c->salts.end) return fail(c,"private PCS replay final cursor differs");
    for(uint64_t i=0;i<rows;++i) if(current[i]>c->salts.end || current[i]<=c->salts.geometry.origin ||
        (i && current[i]<=current[i-1]) || (current[i]-c->salts.geometry.origin)%8)
        return fail(c,"private PCS replay row cursor differs");
    if(retire_private(c,c->salts.band) || retire_private(c,c->salts.current) || retire_private(c,c->salts.meta)) return -1;
    *consumed=c->salts.completed_bytes; c->salts={}; return 0;
}

namespace {
bool linear_session(C71RangeContext* c,uint64_t token) {
    if(!token || c->linear.phase!=1 || token!=c->linear.meta) {
        fail(c,"linear round capability or phase differs"); return false;
    }
    auto* meta=buffer(c,token);
    if(!full(meta,C71_LINEAR_PRIVATE)) { fail(c,"linear private packet retired or unpublished"); return false; }
    return true;
}
template<class T> const T* linear_span(C71RangeContext* c,unsigned index) {
    auto* meta=ptr<uint8_t>(c,buffer(c,c->linear.meta));
    return reinterpret_cast<const T*>(meta+c->linear.offsets[index]);
}
int retire_linear(C71RangeContext* c,uint64_t& id) {
    auto* b=buffer(c,id);
    if(!b || b->kind!=C71_LINEAR_PRIVATE) return fail(c,"linear private retirement type");
    if(checked(c,cudaFree(b->allocation))) { b->release_failed=true; return -1; }
    if(c->account) c->account(-int64_t(b->capacity));
    *b={}; id=0; ++c->stats.releases; recount(c); return 0;
}
}
extern "C" int c71_linear_begin(C71RangeContext* c,c71_linear::Shape shape,const c71_linear::Chunk* chunks,
    const Fp3* tables,uint32_t table_count,const c71_linear::Group* groups,
    const c71_linear::Interval* intervals,const Fp3* points,uint64_t* token) {
    if(!ready(c)) return -1;
    uintptr_t token_end=0;
    if(!token || reinterpret_cast<uintptr_t>(token)%alignof(uint64_t) || !c71_dense::span(token,8,token_end) ||
       !c71_linear::valid(shape) || table_count>1280 || c->linear.phase || c->salts.phase || c->source.values[0])
        return fail(c,"linear begin shape, output or active consumer");
    const void* arrays[]={&shape,chunks,tables,groups,intervals,points};
    const uint64_t lengths[]={sizeof(shape),uint64_t(shape.chunks)*sizeof(*chunks),uint64_t(table_count)*sizeof(*tables),
        uint64_t(shape.groups)*sizeof(*groups),uint64_t(shape.intervals)*sizeof(*intervals),uint64_t(shape.points)*sizeof(*points)};
    const unsigned alignments[]={alignof(c71_linear::Shape),alignof(c71_linear::Chunk),alignof(Fp3),
        alignof(c71_linear::Group),alignof(c71_linear::Interval),alignof(Fp3)};
    uint64_t offsets[6]{},bytes=0;
    for(unsigned i=0;i<6;++i) {
        uintptr_t end=0;
        if(lengths[i] && (reinterpret_cast<uintptr_t>(arrays[i])%alignments[i] ||
            !c71_dense::span(arrays[i],lengths[i],end) || c71_dense::overlaps(token,token_end,arrays[i],end)))
            return fail(c,"linear packet host span, alignment or token alias");
        offsets[i]=bytes; bytes+=aligned(lengths[i]);
    }
    if(bytes>caps[C71_LINEAR_PRIVATE] || !c71_linear::valid_packet(shape,chunks,tables,table_count,groups,intervals,points))
        return fail(c,"linear packet noncanonical or incomplete");
    *token=0;
    auto& s=c->linear; s.shape=shape; s.phase=1;
    std::memcpy(s.offsets,offsets,sizeof(offsets));
    if(allocate(c,C71_LINEAR_PRIVATE,bytes,&s.meta) || allocate(c,C71_LINEAR_PRIVATE,sizeof(c71_linear::Result),&s.output) ||
       allocate(c,C71_LINEAR_PRIVATE,4,&s.flag)) return -1;
    auto* meta=ptr<uint8_t>(c,buffer(c,s.meta));
    bool submitted_error=false;
    for(unsigned i=0;i<6;++i) if(lengths[i]) {
        if(checked(c,cudaMemcpyAsync(meta+offsets[i],arrays[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.h2d_bytes+=lengths[i];
    }
    if(!submitted_error) {
        if(checked(c,cudaMemsetAsync(ptr<void>(c,buffer(c,s.output)),0,sizeof(c71_linear::Result),c->stream))) submitted_error=true;
        else c->stats.zeroed_bytes+=sizeof(c71_linear::Result);
    }
    if(!submitted_error) {
        if(checked(c,cudaMemsetAsync(ptr<void>(c,buffer(c,s.flag)),0,4,c->stream))) submitted_error=true;
        else c->stats.zeroed_bytes+=4;
    }
    // Drain any accepted copy even on a later submit error, while the host
    // packet and local Shape are still alive. One publication fence.
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    for(auto id:{s.meta,s.output,s.flag}) { auto* b=buffer(c,id); b->initialized=b->count; }
    *token=s.meta; return 0;
}
extern "C" int c71_linear_source_tile(C71RangeContext* c,uint64_t token,uint64_t input,c71_pcs::SourceTile tile) {
    if(!ready(c)) return -1;
    if(!linear_session(c,token)) return -1;
    auto& s=c->linear; auto* original=buffer(c,input);
    if(s.mode==2 || !original || (original->kind!=C71_I16 && original->kind!=C71_I64) ||
       original->initialized!=original->count || !c71_pcs::valid(tile,original->kind,original->count,s.shape.live))
        return fail(c,"linear original tile type, coverage or mode");
    const uint64_t visited=tile.rows*tile.columns*tile.width;
    if(visited>s.shape.live-s.visited) return fail(c,"linear original tile excess coverage");
    if(launched(c,c71_linear_source_launch(c->stream,ptr<void>(c,original),original->kind,tile,s.shape,
        linear_span<c71_linear::Chunk>(c,1),linear_span<Fp3>(c,2),linear_span<c71_linear::Group>(c,3),
        linear_span<c71_linear::Interval>(c,4),linear_span<Fp3>(c,5),
        ptr<c71_linear::Result>(c,buffer(c,s.output)),ptr<uint32_t>(c,buffer(c,s.flag))))) return -1;
    // The canonical adapter, not this count, owns unique source-row coverage.
    s.visited+=visited; s.mode=1; return 0;
}
extern "C" int c71_linear_weights(C71RangeContext* c,uint64_t token,uint64_t sealed_tiles) {
    if(!ready(c)) return -1;
    if(!linear_session(c,token)) return -1;
    auto& s=c->linear; auto* tiles=buffer(c,sealed_tiles);
    if(s.mode || s.visited || !c->stats.weights_sealed || !full(tiles,C71_PCS_WEIGHT_TILES) ||
       tiles->visits!=s.shape.live || s.shape.live!=c->stats.weights_bytes/2)
        return fail(c,"linear sealed W mapping, live prefix or duplicate scan");
    if(launched(c,c71_linear_weights_launch(c->stream,c->weights,ptr<c71_pcs::WeightTile>(c,tiles),tiles->count,0,s.shape.live,
        s.shape,linear_span<c71_linear::Chunk>(c,1),linear_span<Fp3>(c,2),linear_span<c71_linear::Group>(c,3),
        linear_span<c71_linear::Interval>(c,4),linear_span<Fp3>(c,5),
        ptr<c71_linear::Result>(c,buffer(c,s.output)),ptr<uint32_t>(c,buffer(c,s.flag))))) return -1;
    s.visited=s.shape.live; s.mode=2; return 0;
}
extern "C" int c71_linear_finish(C71RangeContext* c,uint64_t token,Fp3* output) {
    if(!ready(c)) return -1;
    uintptr_t end=0;
    if(!linear_session(c,token) || !output || reinterpret_cast<uintptr_t>(output)%alignof(Fp3) ||
       !c71_dense::span(output,sizeof(c71_linear::Result),end) || !c->linear.mode || c->linear.visited!=c->linear.shape.live)
        return fail(c,"linear finish output or original scan incomplete");
    c71_linear::Result staged{}; uint32_t flag=0;
    auto& s=c->linear;
    bool submitted_error=false;
    if(checked(c,cudaMemcpyAsync(&staged,ptr<void>(c,buffer(c,s.output)),sizeof(staged),cudaMemcpyDeviceToHost,c->stream)))
        submitted_error=true;
    else c->stats.d2h_bytes+=sizeof(staged);
    if(!submitted_error) {
        if(checked(c,cudaMemcpyAsync(&flag,ptr<void>(c,buffer(c,s.flag)),4,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=4;
    }
    const int synced=fence(c); // staging lives through deferred-driver errors
    if(submitted_error || synced) return -1;
    if(flag) return fail(c,"linear original arithmetic failed");
    for(auto value:staged.values) if(!canonical(value)) return fail(c,"linear noncanonical result");
    if(retire_linear(c,s.flag) || retire_linear(c,s.output) || retire_linear(c,s.meta)) return -1;
    std::memcpy(output,staged.values,sizeof(staged)); s={}; return 0;
}

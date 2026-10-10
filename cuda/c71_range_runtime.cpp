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
cudaError_t c71_pcs_short_pairs_launch(cudaStream_t,const uint64_t*,const uint64_t*,c71_pcs::Hash32*,
    uint64_t,uint64_t,uint64_t,uint32_t*);
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
cudaError_t c71_pcs_query_weight_low_launch(cudaStream_t,const int16_t*,const c71_pcs::WeightTile*,uint64_t,uint64_t,
    const uint64_t*,uint64_t,uint64_t*,uint64_t,c71_pcs::QueryBlock);
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
cudaError_t c71_pcs_residual_weights_launch(cudaStream_t,const int16_t*,uint64_t,const c71_pcs::WeightTile*,uint64_t,uint64_t,uint64_t,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,c71_pcs_residual::Phase,
    c71_pcs_residual::Output,c71_pcs_residual::CosetShape,const uint64_t*,c71_pcs_residual::PowerShape,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,uint32_t*);
cudaError_t c71_pcs_residual_source_launch(cudaStream_t,const void*,uint64_t,unsigned,c71_pcs::SourceTile,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,c71_pcs_residual::Phase,
    c71_pcs_residual::Output,c71_pcs_residual::CosetShape,const uint64_t*,c71_pcs_residual::PowerShape,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,uint32_t*);
cudaError_t c71_pcs_residual_resident_launch(cudaStream_t,c71_pcs_residual::ConstPlanes,uint64_t,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,c71_pcs_residual::Phase,
    c71_pcs_residual::Output,c71_pcs_residual::CosetShape,const uint64_t*,c71_pcs_residual::PowerShape,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,uint32_t*);
cudaError_t c71_pcs_residual_contract_weights_launch(cudaStream_t,const int16_t*,uint64_t,const c71_pcs::WeightTile*,uint64_t,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,unsigned,uint64_t,uint32_t,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,c71_pcs_residual::E*,uint32_t*);
cudaError_t c71_pcs_residual_contract_resident_launch(cudaStream_t,c71_pcs_residual::ConstPlanes,uint64_t,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,unsigned,uint64_t,uint32_t,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,c71_pcs_residual::E*,uint32_t*);
cudaError_t c71_pcs_residual_coset_powers_launch(cudaStream_t,uint64_t*,uint64_t*,c71_pcs_residual::Shape,c71_pcs_residual::CosetShape);
cudaError_t c71_pcs_residual_ood_powers_launch(cudaStream_t,c71_pcs_residual::E*,c71_pcs_residual::E*,c71_pcs_residual::PowerShape,c71_pcs_residual::E);
cudaError_t c71_pcs_residual_pad_launch(cudaStream_t,uint64_t*,const c71_pcs_residual::E*,const uint64_t*,const uint64_t*,
    c71_pcs_residual::Shape,c71_pcs_residual::CosetShape,uint32_t*);
cudaError_t c71_pcs_residual_ood_pad_launch(cudaStream_t,c71_pcs_residual::E*,const c71_pcs_residual::E*,uint32_t,uint64_t,c71_pcs_residual::E,uint32_t*);
cudaError_t c71_pcs_residual_query_weights_launch(cudaStream_t,const int16_t*,uint64_t,
    const c71_pcs::WeightTile*,uint64_t,c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,
    const c71_pcs_residual::E*,const c71_pcs_residual::E*,uint64_t,uint64_t*,uint64_t,c71_pcs::QueryBlock,uint32_t*,unsigned*);
cudaError_t c71_pcs_residual_query_resident_launch(cudaStream_t,c71_pcs_residual::ConstPlanes,uint64_t,
    c71_pcs_residual::Shape,const c71_pcs_residual::Chunk*,const c71_pcs_residual::E*,
    const c71_pcs_residual::E*,uint64_t,uint64_t*,uint64_t,c71_pcs::QueryBlock,uint32_t*);
cudaError_t c71_pcs_residual_fold_launch(cudaStream_t,c71_pcs_residual::ConstPlanes,c71_pcs_residual::Planes,
    uint64_t,unsigned,c71_pcs_residual::E,c71_pcs_residual::E,uint32_t*);
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
    uint32_t residual_role=0;
    uint64_t residual_group=0;
};
struct LinearTransaction {
    c71_linear::Shape shape{};
    uint64_t meta=0,output=0,flag=0,offsets[6]{},visited=0;
    uint32_t phase=0,mode=0;
};
static_assert(sizeof(LinearTransaction)==120);
struct ResidualTransaction {
    c71_pcs_residual::Shape shape{};
    c71_pcs_residual::CosetShape cosets{};
    c71_pcs_residual::PowerShape powers{};
    c71_pcs_residual::E point{};
    c71_pcs_residual::Phase phase=c71_pcs_residual::Phase::singleton;
    uint64_t meta=0,offsets[4]{},low=0,high=0,scratch=0,twiddles=0,flag=0,reduced=0,planes[3]{},ring=0,visited=0;
    uint32_t active=0,mode=0,pad_count=0;
};
struct ContractTransaction {
    c71_pcs_residual::Shape shape{};
    uint64_t meta=0,offsets[3]{},band=0,output=0,flag=0,cursor=0,visited=0,source[3]{};
    uint32_t active=0,kind=0,capacity=0,mode=0;
};
struct ResidualQueryTransaction {
    c71_pcs_residual::Shape shape{};
    uint64_t meta=0,offsets[4]{},low=0,flag=0,cursor=0,source[3]{},last[3]{};
    uint32_t phase=0,mode=0,pad_rows=0,capacity=0,column=0,loaded=0,mask=0;
};
struct C71RangeContext {
    C71RangeAccount account=nullptr;
    int device=0;
    cudaStream_t stream=nullptr;
    int16_t* weights=nullptr;
    uint64_t usable=0;
    Buffer buffers[512]{};
    uint64_t numeric_flag=0;
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
        uint64_t first=0,short_ring=0,short_output=0;
    } salts;
    LinearTransaction linear{};
    ResidualTransaction residual{};
    ContractTransaction contract{};
    ResidualQueryTransaction residual_query{};
};
namespace {
constexpr uint64_t sizes[]={1,2,48,96,24,96,8,1,8,8,32,32,32,40,8,8,8,1,1,8};
constexpr uint64_t caps[]={uint64_t{1}<<31,uint64_t{1}<<27,uint64_t{1}<<24,
                          uint64_t{1}<<24,256*32*32,65536,uint64_t(c71_dense::max_m)*c71_dense::max_n,uint64_t{1}<<31,65535,
                          uint64_t{1}<<28,uint64_t{1}<<25,uint64_t{1}<<25,uint64_t{1}<<26,65536,uint64_t{1}<<25,
                          uint64_t{1}<<28,256,uint64_t{1}<<28,uint64_t{1}<<30,uint64_t{1}<<28};
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
    if(checked(c,cudaSetDevice(device))) return -1;
    // sm_90 kernels need at most 216 B; avoid the unused default stack reserve.
    size_t stack=0;
    if(checked(c,cudaDeviceSetLimit(cudaLimitStackSize,256)) ||
       checked(c,cudaDeviceGetLimit(&stack,cudaLimitStackSize))) return -1;
    if(stack!=256) return fail(c,"CUDA initial stack reservation differs");
    if(checked(c,cudaStreamCreateWithFlags(&c->stream,cudaStreamNonBlocking))) return -1;
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
    if(!out || kind>C71_PCS_RESIDUAL_PRIVATE || !count || count>caps[kind]) return fail(c,"range allocation shape");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
int dense_flag(C71RangeContext* c,uint64_t* id,bool numeric=false) {
    // Only synchronous numeric calls share this flag; PCS/byte transactions
    // keep their own sticky flags while producers use the same stream.
    if(numeric) {
        if(!c->numeric_flag && allocate(c,C71_PCS_PRIVATE,4,&c->numeric_flag)) return -1;
        *id=c->numeric_flag;
    } else if(c71_range_alloc(c,C71_U8,4,id)) return -1;
    if(checked(c,cudaMemsetAsync(ptr<void>(c,buffer(c,*id)),0,4,c->stream))) return -1;
    c->stats.zeroed_bytes+=4; return 0;
}
int dense_complete(C71RangeContext* c,uint64_t flag,Buffer* output) {
    uint32_t failed=0;
    if(checked(c,cudaMemcpyAsync(&failed,ptr<void>(c,buffer(c,flag)),4,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=4;
    if(fence(c)) return -1;
    if(failed) return fail(c,"dense device arithmetic rejection");
    // Completion keeps a reusable flag charged; dedicated flags are freed
    // after the same fence. Public release still requires its own fence.
    if(flag!=c->numeric_flag) {
        auto* completed_flag=buffer(c,flag);
        if(checked(c,cudaFree(completed_flag->allocation))) { completed_flag->release_failed=true; return -1; }
        if(c->account) c->account(-int64_t(completed_flag->capacity));
        *completed_flag={}; ++c->stats.releases; recount(c);
    }
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    if(context->residual_query.phase) return fail(context,"PCS E query keeps inputs and workspaces private");
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
    uint64_t flag=0; if(dense_flag(context,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(context,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(context,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(context,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    uint64_t flag=0; if(dense_flag(c,&flag,true)) return -1;
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
    if(dense_flag(c,&flag,true) || c71_range_alloc(c,C71_U8,rows*4,&tokens)) return -1;
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
    if(rows>caps[C71_PCS_FRONTIER_PENDING]/levels || b->count!=rows*levels) return fail(c,"PCS frontier capacity");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps remainder lineage immutable");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
extern "C" int c71_pcs_query_weight_low(C71RangeContext* c,uint64_t tiles,uint64_t pads,uint64_t low,c71_pcs::QueryBlock s) {
    if(!ready(c)) return -1;
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
    auto* t=buffer(c,tiles); auto* p=buffer(c,pads); auto* l=buffer(c,low);
    if(!c->stats.weights_sealed || !c->weights || !full(t,C71_PCS_WEIGHT_TILES) ||
       t->visits!=c->stats.weights_bytes/2 || !full(p,C71_PCS_BASE) ||
       !l || l->kind!=C71_PCS_BASE || p==l ||
       !c71_pcs::valid_query_weight_low(s,l->count,t->visits,p->count))
        return fail(c,"PCS query original W geometry, sealed mapping, pads or type");
    if(launched(c,c71_pcs_query_weight_low_launch(c->stream,c->weights,ptr<c71_pcs::WeightTile>(c,t),t->count,t->visits,
        ptr<uint64_t>(c,p),p->count,ptr<uint64_t>(c,l),l->count,s))) return -1;
    l->initialized=l->count; return 0; // The existing final read fences this stream.
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
    if(c->residual_query.phase && (c->residual_query.phase!=2 || !children ||
       h->residual_group!=c->residual_query.meta || h->residual_role<3 || h->residual_role>5 ||
       h->visits!=2*degree || high!=c->residual_query.last[h->residual_role-3]))
        return fail(c,"PCS E query child lineage or phase differs");
    if(c->residual_query.phase) for(unsigned limb=0;limb<3;++limb)
        if(limb!=h->residual_role-3 && output==c->residual_query.last[limb])
            return fail(c,"PCS E query child overwrites another limb");
    unsigned attempted=0; uint64_t copied=0;
    const auto status=c71_pcs_query_remainder_launch(c->stream,ptr<uint64_t>(c,h),ptr<uint64_t>(c,l),
        ptr<uint64_t>(c,i),ptr<uint64_t>(c,m),ptr<uint64_t>(c,f),ptr<uint64_t>(c,b),ptr<uint64_t>(c,w),
        ptr<uint64_t>(c,s),ptr<uint64_t>(c,o),degree,o->count,children,&attempted,&copied);
    c->stats.launches+=attempted; c->stats.d2d_bytes+=copied;
    if(checked(c,status)) return -1;
    o->initialized=o->count;
    if(c->residual_query.phase) { o->residual_group=c->residual_query.meta; o->residual_role=h->residual_role; o->visits=degree;
        c->residual_query.last[o->residual_role-3]=output; }
    return 0; // final bounded read fences the same stream
}
extern "C" int c71_pcs_query_shift(C71RangeContext* c,uint64_t values,uint64_t shift,uint64_t forward,uint64_t backward,
    uint64_t work,uint64_t scratch,uint64_t low,uint64_t high) {
    if(!ready(c)) return -1;
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
    auto* v=buffer(c,values); auto* a=buffer(c,correction);
    if(!full(v,C71_PCS_BASE) || !full(a,C71_PCS_BASE) || v==a || v->count!=a->count || v->count>(uint64_t{1}<<20))
        return fail(c,"PCS query correction geometry or alias");
    return launched(c,c71_pcs_query_add_launch(c->stream,ptr<uint64_t>(c,v),ptr<uint64_t>(c,a),v->count));
}
extern "C" int c71_pcs_ring_zero(C71RangeContext* c,uint64_t out) {
    if(!ready(c)) return -1;
    if(c->residual_query.phase) return fail(c,"PCS E query keeps inputs and workspaces private");
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
    if(!c71_pcs::valid(s) || c->source.values[0] || c->linear.phase || c->residual.active || c->contract.active || c->residual_query.phase || !a || !b || a==b || a->flag || b->flag ||
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
    // KV reserves future rows; only its initialized prefix is an original source.
    if(!c->source.values[0] || !input || (input->kind!=C71_I16 && input->kind!=C71_I64) || input->initialized>input->count ||
       !tile || !c71_pcs::valid(*tile,input->kind,input->initialized,s.live)) return fail(c,"PCS original source tile or state");
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
       !count || count!=std::min(uint64_t{65536},c->salts.group_cosets==2?c->salts.geometry.rows:rows) ||
       first>rows || count>rows-first || (c->salts.group_cosets==2 && count>c->salts.geometry.rows-first%c->salts.geometry.rows)) {
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
int private_hash_complete(C71RangeContext* c,Buffer* out,uint64_t count,uint64_t* completed,uint64_t expected_leaves=0) {
    if(!expected_leaves) expected_leaves=out->count;
    c->salts.first+=count;
    if(c->salts.first!=expected_leaves) { *completed=c->salts.completed_bytes; return 0; }
    uint64_t consumed=0;
    if(checked(c,cudaMemcpyAsync(&consumed,&private_meta(c)->consumed,8,cudaMemcpyDeviceToHost,c->stream))) return -1;
    c->stats.d2h_bytes+=8;
    if(dense_complete(c,out->flag,out)) return -1;
    const uint64_t total=c->salts.end-c->salts.geometry.origin;
    const uint64_t minimum=uint64_t(c->salts.group+1)*expected_leaves*32;
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
    if(!session || !seed || c->salts.phase || c->linear.phase || c->residual.active || c->contract.active || c->residual_query.phase || !c71_salts::valid(g) || g.cut<g.cosets ||
       (group_cosets!=2 && group_cosets!=4 && group_cosets!=32) || group_cosets>g.cosets ||
       (group_cosets==2 ? (g.cosets<2 || g.rows>(uint64_t{1}<<23) || g.rows*g.cosets>(uint64_t{1}<<32) ||
           (g.rows>(uint64_t{1}<<20) && g.cut!=4096)) : g.rows>(uint64_t{1}<<20)) ||
       !c71_salts::valid_capacity(capacity))
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

extern "C" int c71_pcs_short_leaves_private(C71RangeContext* c,uint64_t session,uint64_t ring,uint64_t states,
    uint32_t group,uint64_t first,uint64_t count,uint64_t* completed) {
    if(!ready(c)) return -1;
    auto* values=buffer(c,ring); auto* out=buffer(c,states);
    const auto geometry=c->salts.geometry;
    uintptr_t end=0;
    if(!completed || reinterpret_cast<uintptr_t>(completed)%8 || !c71_dense::span(completed,8,end) ||
       !private_band(c,session,group,first,count) || c->salts.group_cosets!=2 || geometry.rows>(uint64_t{1}<<23) ||
       c->residual.active || c->contract.active || !full(values,C71_PCS_RESIDUAL_PRIVATE) ||
       values->residual_role!=2 || values->count!=24*geometry.rows ||
       values->visits!=((uint64_t(geometry.cosets)<<32)|uint64_t(2*group)) ||
       !out || out->kind!=C71_PCS_HASH_PENDING || out->count!=geometry.rows || first!=out->visits ||
       (first==0 ? (out->flag || out->initialized || c->salts.short_ring || c->salts.short_output) :
           (!out->flag || out->initialized!=std::min(first,geometry.rows) ||
            ring!=c->salts.short_ring || states!=c->salts.short_output)))
        return fail(c,"private PCS paired S1 leaf type, geometry, ring binding or coverage");
    if(!first && dense_flag(c,&out->flag)) return -1;
    if(private_replay(c,out,first,count) || launched(c,c71_pcs_short_pairs_launch(c->stream,ptr<uint64_t>(c,values),
        ptr<uint64_t>(c,buffer(c,c->salts.band)),ptr<c71_pcs::Hash32>(c,out),geometry.rows,first,count,
        ptr<uint32_t>(c,buffer(c,out->flag))))) return -1;
    c->salts.short_ring=ring; c->salts.short_output=states;
    out->visits+=count; out->initialized=std::min(out->visits,geometry.rows);
    const auto result=private_hash_complete(c,out,count,completed,2*geometry.rows);
    if(!result && !c->salts.first) c->salts.short_ring=c->salts.short_output=0;
    return result;
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
       !c71_linear::valid(shape) || table_count>1280 || c->linear.phase || c->salts.phase || c->source.values[0] || c->residual.active || c->contract.active || c->residual_query.phase)
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
       original->initialized>original->count || !c71_pcs::valid(tile,original->kind,original->initialized,s.shape.live))
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

namespace {
namespace residual=c71_pcs_residual;
constexpr unsigned residual_plane_role=3, residual_ring_role=2;
bool residual_idle(C71RangeContext* c) {
    if(c->residual_query.phase || c->residual.active || c->contract.active || c->linear.phase || c->salts.phase || c->source.values[0]) {
        fail(c,"PCS residual consumer already active"); return false;
    }
    return true;
}
bool residual_session(C71RangeContext* c,uint64_t token) {
    if(!token || !c->residual.active || token!=c->residual.meta || !full(buffer(c,token),C71_PCS_PRIVATE)) {
        fail(c,"PCS residual capability or private packet differs"); return false;
    }
    return true;
}
int residual_retire(C71RangeContext* c,uint64_t& id) {
    if(!id) return 0;
    auto* b=buffer(c,id);
    if(!b || (b->kind!=C71_PCS_PRIVATE && b->kind!=C71_PCS_RESIDUAL_PRIVATE))
        return fail(c,"PCS residual retirement type");
    if(checked(c,cudaFree(b->allocation))) { b->release_failed=true; return -1; }
    if(c->account) c->account(-int64_t(b->capacity));
    *b={}; id=0; ++c->stats.releases; recount(c); return 0;
}
int residual_zero(C71RangeContext* c,uint64_t id) {
    auto* b=buffer(c,id);
    if(!b || b->initialized) return fail(c,"PCS residual zero state");
    if(checked(c,cudaMemsetAsync(ptr<void>(c,b),0,b->count*sizes[b->kind],c->stream))) return -1;
    c->stats.zeroed_bytes+=b->count*sizes[b->kind]; return 0;
}
residual::Planes residual_outputs(C71RangeContext* c) {
    auto& s=c->residual;
    return {s.planes[0]?ptr<uint64_t>(c,buffer(c,s.planes[0])):nullptr,
        s.planes[1]?ptr<uint64_t>(c,buffer(c,s.planes[1])):nullptr,
        s.planes[2]?ptr<uint64_t>(c,buffer(c,s.planes[2])):nullptr};
}
residual::Output residual_output(C71RangeContext* c) {
    auto& s=c->residual;
    return {residual_outputs(c),s.ring?ptr<uint64_t>(c,buffer(c,s.ring)):nullptr,
        s.reduced?ptr<residual::E>(c,buffer(c,s.reduced)):nullptr};
}
template<class T> const T* residual_packet(C71RangeContext* c,unsigned span,bool present) {
    if(!present) return nullptr;
    return reinterpret_cast<const T*>(ptr<uint8_t>(c,buffer(c,c->residual.meta))+c->residual.offsets[span]);
}
bool residual_planes(C71RangeContext* c,C71PcsResidualPlanes p,residual::ConstPlanes& values) {
    if(!p.c0 || !p.c1 || !p.c2 || p.c0==p.c1 || p.c0==p.c2 || p.c1==p.c2 ||
       !power2(p.count) || p.count>(uint64_t{1}<<28)) { fail(c,"PCS residual plane geometry or alias"); return false; }
    auto* a=buffer(c,p.c0); auto* b=buffer(c,p.c1); auto* d=buffer(c,p.c2);
    Buffer* ordered[]={a,b,d};
    for(unsigned limb=0;limb<3;++limb) if(!full(ordered[limb],C71_PCS_RESIDUAL_PRIVATE) || ordered[limb]->count!=p.count ||
        ordered[limb]->residual_role!=residual_plane_role+limb || ordered[limb]->residual_group!=p.c0) {
        fail(c,"PCS residual plane generation, coverage or type"); return false;
    }
    values={ptr<uint64_t>(c,a),ptr<uint64_t>(c,b),ptr<uint64_t>(c,d)}; return true;
}
int residual_submit(C71RangeContext* c,uint64_t input,const c71_pcs::SourceTile* tile,
    const C71PcsResidualPlanes* resident_planes,uint64_t sealed_weights) {
    auto& s=c->residual;
    const auto* chunks=residual_packet<residual::Chunk>(c,1,s.shape.equality.chunks!=0);
    const auto* tables=residual_packet<residual::E>(c,2,s.shape.equality.entries!=0);
    const uint64_t* high=s.phase==residual::Phase::cosets?ptr<uint64_t>(c,buffer(c,s.high)):nullptr;
    const auto* low_power=s.phase==residual::Phase::ood?ptr<residual::E>(c,buffer(c,s.low)):nullptr;
    const auto* high_power=s.phase==residual::Phase::ood?ptr<residual::E>(c,buffer(c,s.high)):nullptr;
    auto* flag=ptr<uint32_t>(c,buffer(c,s.flag));
    uint64_t visits=0;
    cudaError_t status=cudaSuccess;
    if(tile) {
        auto* original=buffer(c,input);
        if(s.mode==2 || s.mode==3 || !original || (original->kind!=C71_I16 && original->kind!=C71_I64) ||
           original->initialized>original->count || !c71_pcs::valid(*tile,original->kind,original->initialized,s.shape.live))
            return fail(c,"PCS residual original tile type, coverage or mode");
        visits=tile->rows*tile->columns*tile->width;
        // The trusted canonical adapter owns exact unique source-row coverage.
        // This boundary validates spans/count, as for the initial native A PCS.
        if(visits>s.shape.live-s.visited)
            return fail(c,"PCS residual original tile excess");
        status=c71_pcs_residual_source_launch(c->stream,ptr<void>(c,original),original->initialized,original->kind,*tile,
            s.shape,chunks,tables,s.phase,residual_output(c),s.cosets,high,s.powers,low_power,high_power,flag);
        s.mode=1;
    } else if(resident_planes) {
        residual::ConstPlanes values{};
        if(s.mode || s.visited || s.shape.live!=resident_planes->count ||
           s.shape.dimension>28 || resident_planes->count!=(uint64_t{1}<<s.shape.dimension) ||
           (s.phase!=residual::Phase::singleton && s.shape.dimension-s.shape.remaining>2) ||
           !residual_planes(c,*resident_planes,values)) return fail(c,"PCS residual resident source shape or generation");
        visits=resident_planes->count;
        status=c71_pcs_residual_resident_launch(c->stream,values,visits,s.shape,chunks,tables,s.phase,
            residual_output(c),s.cosets,high,s.powers,low_power,high_power,flag);
        s.mode=3;
    } else {
        auto* tiles=buffer(c,sealed_weights);
        if(s.mode || s.visited || !c->stats.weights_sealed || !full(tiles,C71_PCS_WEIGHT_TILES) ||
           tiles->visits!=s.shape.live || s.shape.live!=c->stats.weights_bytes/2)
            return fail(c,"PCS residual sealed W mapping or duplicate scan");
        visits=s.shape.live;
        status=c71_pcs_residual_weights_launch(c->stream,c->weights,c->stats.weights_bytes/2,
            ptr<c71_pcs::WeightTile>(c,tiles),tiles->count,0,visits,s.shape,chunks,tables,s.phase,
            residual_output(c),s.cosets,high,s.powers,low_power,high_power,flag);
        s.mode=2;
    }
    if(launched(c,status)) return -1;
    s.visited+=visits; return 0;
}
int residual_free_aux(C71RangeContext* c) {
    auto& s=c->residual;
    for(auto* id:{&s.flag,&s.scratch,&s.twiddles,&s.low,&s.high,&s.reduced,&s.meta})
        if(residual_retire(c,*id)) return -1;
    return 0;
}
}
extern "C" int c71_pcs_residual_begin(C71RangeContext* c,residual::Shape shape,residual::Phase phase,
    const residual::Chunk* chunks,const residual::E* tables,residual::CosetShape cosets,
    const residual::E* pads,uint32_t pad_count,residual::E point,uint64_t* token) {
    if(!ready(c)) return -1;
    uintptr_t token_end=0;
    const bool salts_bound=!c->salts.phase || (phase==residual::Phase::cosets && c->salts.phase==3 &&
        c->salts.group_cosets==2 && cosets.rows==c->salts.geometry.rows &&
        cosets.cosets==c->salts.geometry.cosets && cosets.first_coset==2*c->salts.group && !c->salts.first);
    if(c->residual_query.phase || c->residual.active || c->contract.active || c->linear.phase || c->source.values[0] || !salts_bound ||
       !token || reinterpret_cast<uintptr_t>(token)%8 || !c71_dense::span(token,8,token_end) ||
       !residual::valid(shape,phase) || !residual::canonical(point) ||
       (phase==residual::Phase::cosets ? (!residual::valid(cosets,shape) || pad_count!=4*cosets.pad_rows || !residual::zero(point)) :
        (!residual::empty(cosets) || (phase!=residual::Phase::ood && (pad_count || !residual::zero(point))))) ||
       pad_count>(1u<<20) || (pad_count && !pads)) return fail(c,"PCS residual begin geometry, phase or output");
    if((phase==residual::Phase::retention && shape.remaining>28)) return fail(c,"PCS residual retained capacity");
    const void* arrays[]={&shape,chunks,tables,pads};
    const uint64_t lengths[]={sizeof(shape),uint64_t(shape.equality.chunks)*sizeof(*chunks),
        uint64_t(shape.equality.entries)*sizeof(*tables),uint64_t(pad_count)*sizeof(*pads)};
    const unsigned alignments[]={alignof(residual::Shape),alignof(residual::Chunk),alignof(residual::E),alignof(residual::E)};
    uint64_t offsets[4]{},bytes=0;
    for(unsigned i=0;i<4;++i) {
        uintptr_t end=0;
        if(lengths[i] && (reinterpret_cast<uintptr_t>(arrays[i])%alignments[i] ||
           !c71_dense::span(arrays[i],lengths[i],end) || c71_dense::overlaps(token,token_end,arrays[i],end)))
            return fail(c,"PCS residual host packet span, alignment or token alias");
        offsets[i]=bytes; bytes+=aligned(lengths[i]);
    }
    if(bytes>caps[C71_PCS_PRIVATE] || !residual::valid_packet(shape.equality,chunks,tables))
        return fail(c,"PCS residual equality packet noncanonical or incomplete");
    for(uint32_t i=0;i<pad_count;++i) if(!residual::canonical(pads[i])) return fail(c,"PCS residual pad noncanonical");
    uint64_t required=aligned(bytes)+aligned(4);
    if(phase==residual::Phase::singleton || phase==residual::Phase::ood)
        required+=aligned((phase==residual::Phase::singleton?128:1)*sizeof(residual::E));
    else if(phase==residual::Phase::retention) required+=3*aligned((uint64_t{1}<<shape.remaining)*8);
    else required+=aligned(24*cosets.rows*8)+aligned(2*cosets.rows*8)+
        aligned(2*residual::high_rows(shape,cosets)*8)+2*aligned(cosets.rows*8);
    if(phase==residual::Phase::ood) {
        const residual::PowerShape powers{shape.remaining,(shape.remaining+1)/2,0,0};
        required+=aligned(residual::low_count(powers)*sizeof(residual::E))+
            aligned(residual::high_count(powers)*sizeof(residual::E));
    }
    if(required>c->usable || c->stats.arena_bytes>c->usable-required)
        return fail(c,"PCS residual simultaneous arena admission failed");
    *token=0;
    auto& s=c->residual; s.shape=shape; s.phase=phase; s.cosets=cosets; s.point=point; s.pad_count=pad_count; s.active=1;
    std::memcpy(s.offsets,offsets,sizeof(offsets));
    if(allocate(c,C71_PCS_PRIVATE,bytes,&s.meta) || allocate(c,C71_PCS_PRIVATE,4,&s.flag)) return -1;
    if(phase==residual::Phase::singleton || phase==residual::Phase::ood) {
        const uint64_t count=phase==residual::Phase::singleton ? 128 : 1;
        if(allocate(c,C71_PCS_PRIVATE,count*sizeof(residual::E),&s.reduced)) return -1;
    } else if(phase==residual::Phase::retention) {
        for(auto& id:s.planes) if(allocate(c,C71_PCS_RESIDUAL_PRIVATE,uint64_t{1}<<shape.remaining,&id)) return -1;
    } else {
        const uint64_t rows=cosets.rows;
        if(allocate(c,C71_PCS_RESIDUAL_PRIVATE,24*rows,&s.ring) ||
           allocate(c,C71_PCS_PRIVATE,2*rows*8,&s.low) ||
           allocate(c,C71_PCS_PRIVATE,2*residual::high_rows(shape,cosets)*8,&s.high) ||
           allocate(c,C71_PCS_PRIVATE,rows*8,&s.scratch) || allocate(c,C71_PCS_PRIVATE,rows*8,&s.twiddles)) return -1;
    }
    if(phase==residual::Phase::ood) {
        s.powers={shape.remaining,(shape.remaining+1)/2,0,0};
        if(allocate(c,C71_PCS_PRIVATE,residual::low_count(s.powers)*sizeof(residual::E),&s.low) ||
           allocate(c,C71_PCS_PRIVATE,residual::high_count(s.powers)*sizeof(residual::E),&s.high)) return -1;
    }
    bool submitted_error=false;
    auto* meta=ptr<uint8_t>(c,buffer(c,s.meta));
    for(unsigned i=0;i<4;++i) if(lengths[i]) {
        if(checked(c,cudaMemcpyAsync(meta+offsets[i],arrays[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.h2d_bytes+=lengths[i];
    }
    if(!submitted_error) for(auto id:{s.flag,s.reduced,s.planes[0],s.planes[1],s.planes[2],s.ring})
        if(id && residual_zero(c,id)) { submitted_error=true; break; }
    if(!submitted_error && phase==residual::Phase::cosets) {
        if(launched(c,c71_pcs_residual_coset_powers_launch(c->stream,ptr<uint64_t>(c,buffer(c,s.low)),
            ptr<uint64_t>(c,buffer(c,s.high)),shape,cosets))) submitted_error=true;
        if(!submitted_error) {
            unsigned log=0; while((uint64_t{1}<<log)<cosets.rows) ++log;
            if(launched(c,c71_pcs_transform_twiddles_launch(c->stream,ptr<uint64_t>(c,buffer(c,s.twiddles)),log,0))) submitted_error=true;
        }
    }
    if(!submitted_error && phase==residual::Phase::ood &&
       launched(c,c71_pcs_residual_ood_powers_launch(c->stream,ptr<residual::E>(c,buffer(c,s.low)),
           ptr<residual::E>(c,buffer(c,s.high)),s.powers,point))) submitted_error=true;
    // Drain accepted uploads while the host packet and Shape still exist,
    // including a later failed submit. No capability is published on failure.
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    buffer(c,s.meta)->initialized=buffer(c,s.meta)->count;
    *token=s.meta; return 0;
}
extern "C" int c71_pcs_residual_source_tile(C71RangeContext* c,uint64_t token,uint64_t input,c71_pcs::SourceTile tile) {
    if(!ready(c) || !residual_session(c,token)) return -1;
    return residual_submit(c,input,&tile,nullptr,0);
}
extern "C" int c71_pcs_residual_weights(C71RangeContext* c,uint64_t token,uint64_t sealed_tiles) {
    if(!ready(c) || !residual_session(c,token)) return -1;
    return residual_submit(c,0,nullptr,nullptr,sealed_tiles);
}
extern "C" int c71_pcs_residual_resident(C71RangeContext* c,uint64_t token,C71PcsResidualPlanes planes) {
    if(!ready(c) || !residual_session(c,token)) return -1;
    return residual_submit(c,0,nullptr,&planes,0);
}
extern "C" int c71_pcs_residual_finish(C71RangeContext* c,uint64_t token,C71PcsResidualResult* output) {
    if(!ready(c) || !residual_session(c,token)) return -1;
    uintptr_t end=0;
    auto& s=c->residual;
    if(!output || reinterpret_cast<uintptr_t>(output)%alignof(C71PcsResidualResult) ||
       !c71_dense::span(output,sizeof(*output),end) || !s.mode || s.visited!=s.shape.live)
        return fail(c,"PCS residual finish output or original scan incomplete");
    bool submitted_error=false;
    if(s.phase==residual::Phase::cosets) {
        if(launched(c,c71_pcs_residual_pad_launch(c->stream,ptr<uint64_t>(c,buffer(c,s.ring)),
            residual_packet<residual::E>(c,3,true),ptr<uint64_t>(c,buffer(c,s.low)),ptr<uint64_t>(c,buffer(c,s.high)),
            s.shape,s.cosets,ptr<uint32_t>(c,buffer(c,s.flag))))) submitted_error=true;
        unsigned log=0; while((uint64_t{1}<<log)<s.cosets.rows) ++log;
        for(unsigned column=0;column<24 && !submitted_error;++column) {
            unsigned attempted=0;
            const auto status=c71_pcs_transform_launch(c->stream,ptr<uint64_t>(c,buffer(c,s.ring))+uint64_t(column)*s.cosets.rows,
                ptr<uint64_t>(c,buffer(c,s.scratch)),ptr<uint64_t>(c,buffer(c,s.twiddles)),log,1,0,&attempted);
            c->stats.launches+=attempted;
            if(log%2 && log>1 && attempted>1) c->stats.d2d_bytes+=s.cosets.rows*8;
            if(checked(c,status)) submitted_error=true;
        }
    } else if(s.phase==residual::Phase::ood && s.pad_count &&
        launched(c,c71_pcs_residual_ood_pad_launch(c->stream,ptr<residual::E>(c,buffer(c,s.reduced)),
            residual_packet<residual::E>(c,3,true),s.pad_count,uint64_t{1}<<s.shape.remaining,s.point,
            ptr<uint32_t>(c,buffer(c,s.flag))))) submitted_error=true;
    C71PcsResidualResult staged{};
    staged.reduced_count=s.phase==residual::Phase::singleton ? 1u<<(s.shape.dimension-s.shape.remaining) :
        s.phase==residual::Phase::ood ? 1 : 0;
    if(!submitted_error && staged.reduced_count) {
        const size_t bytes=size_t(staged.reduced_count)*sizeof(residual::E);
        if(checked(c,cudaMemcpyAsync(staged.reduced,ptr<void>(c,buffer(c,s.reduced)),bytes,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=bytes;
    }
    uint32_t flag=0;
    if(!submitted_error) {
        if(checked(c,cudaMemcpyAsync(&flag,ptr<void>(c,buffer(c,s.flag)),4,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=4;
    }
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    if(flag) return fail(c,"PCS residual source/pad arithmetic failed");
    for(unsigned i=0;i<staged.reduced_count;++i) if(!residual::canonical(staged.reduced[i])) return fail(c,"PCS residual result noncanonical");
    staged.planes={s.planes[0],s.planes[1],s.planes[2],s.planes[0]?uint64_t{1}<<s.shape.remaining:0};
    staged.ring=s.ring;
    const auto cosets=s.cosets;
    if(residual_free_aux(c)) return -1;
    if(staged.planes.c0) {
        const uint64_t ids[]={staged.planes.c0,staged.planes.c1,staged.planes.c2};
        for(unsigned limb=0;limb<3;++limb) {
            auto* b=buffer(c,ids[limb]); b->initialized=b->count;
            b->residual_role=residual_plane_role+limb; b->residual_group=staged.planes.c0;
        }
    }
    if(staged.ring) {
        auto* b=buffer(c,staged.ring); b->initialized=b->count; b->residual_role=residual_ring_role;
        b->visits=(uint64_t(cosets.cosets)<<32)|cosets.first_coset;
    }
    *output=staged; s={}; return 0;
}
extern "C" int c71_pcs_residual_fold(C71RangeContext* c,C71PcsResidualPlanes input,uint32_t rounds,
    residual::E r0,residual::E r1,C71PcsResidualPlanes* output) {
    if(!ready(c)) return -1;
    residual::ConstPlanes values{};
    uintptr_t end=0;
    if(!residual_idle(c) || !output || reinterpret_cast<uintptr_t>(output)%alignof(C71PcsResidualPlanes) ||
       !c71_dense::span(output,sizeof(*output),end) || !residual::valid_fold(input.count,rounds,r0,r1) ||
       !residual_planes(c,input,values)) return fail(c,"PCS residual fold generation, output or challenge");
    const uint64_t required=3*aligned((input.count>>rounds)*8)+aligned(4);
    if(required>c->usable || c->stats.arena_bytes>c->usable-required)
        return fail(c,"PCS residual paired fold arena admission failed");
    uint64_t ids[3]{},flag_id=0;
    for(auto& id:ids) if(allocate(c,C71_PCS_RESIDUAL_PRIVATE,input.count>>rounds,&id)) return -1;
    if(allocate(c,C71_PCS_PRIVATE,4,&flag_id)) return -1;
    if(residual_zero(c,flag_id)) return -1;
    residual::Planes target{ptr<uint64_t>(c,buffer(c,ids[0])),ptr<uint64_t>(c,buffer(c,ids[1])),ptr<uint64_t>(c,buffer(c,ids[2]))};
    bool submitted_error=launched(c,c71_pcs_residual_fold_launch(c->stream,values,target,input.count,rounds,r0,r1,
        ptr<uint32_t>(c,buffer(c,flag_id))))!=0;
    uint32_t flag=0;
    if(!submitted_error) {
        if(checked(c,cudaMemcpyAsync(&flag,ptr<void>(c,buffer(c,flag_id)),4,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=4;
    }
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    if(flag) return fail(c,"PCS residual fold noncanonical input");
    if(residual_retire(c,flag_id)) return -1;
    for(unsigned limb=0;limb<3;++limb) {
        auto* b=buffer(c,ids[limb]); b->initialized=b->count;
        b->residual_role=residual_plane_role+limb; b->residual_group=ids[0];
    }
    *output={ids[0],ids[1],ids[2],input.count>>rounds}; return 0;
}
extern "C" int c71_pcs_residual_retire_planes(C71RangeContext* c,C71PcsResidualPlanes planes) {
    if(!ready(c)) return -1;
    residual::ConstPlanes values{};
    if(!residual_idle(c) || !residual_planes(c,planes,values)) return -1;
    if(fence(c)) return -1;
    for(auto* id:{&planes.c0,&planes.c1,&planes.c2}) if(residual_retire(c,*id)) return -1;
    return 0;
}
extern "C" int c71_pcs_residual_retire_ring(C71RangeContext* c,uint64_t ring) {
    if(!ready(c)) return -1;
    auto* b=buffer(c,ring);
    if(c->residual_query.phase || c->residual.active || c->contract.active || c->linear.phase || c->source.values[0] || (c->salts.phase && c->salts.phase!=3 && c->salts.phase!=4) ||
       (c->salts.short_ring==ring && c->salts.first) ||
       !full(b,C71_PCS_RESIDUAL_PRIVATE) || b->residual_role!=residual_ring_role)
        return fail(c,"PCS residual ring retirement type or state");
    if(fence(c)) return -1;
    return residual_retire(c,ring);
}
extern "C" int c71_pcs_residual_final_read(C71RangeContext* c,C71PcsResidualPlanes planes,residual::E* output,uint32_t count) {
    if(!ready(c)) return -1;
    residual::ConstPlanes values{};
    uintptr_t end=0;
    if(!residual_idle(c) || !output || reinterpret_cast<uintptr_t>(output)%alignof(residual::E) ||
       !count || count>128 || count!=planes.count || !c71_dense::span(output,uint64_t(count)*sizeof(*output),end) ||
       !residual_planes(c,planes,values)) return fail(c,"PCS residual final polynomial shape or generation");
    uint64_t limbs[3][128]{};
    const uint64_t* inputs[]={values.c0,values.c1,values.c2};
    bool submitted_error=false;
    for(unsigned component=0;component<3;++component) {
        if(checked(c,cudaMemcpyAsync(limbs[component],inputs[component],uint64_t(count)*8,cudaMemcpyDeviceToHost,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.d2h_bytes+=uint64_t(count)*8;
    }
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    residual::E staged[128]{};
    for(unsigned i=0;i<count;++i) {
        staged[i]={limbs[0][i],limbs[1][i],limbs[2][i]};
        if(!residual::canonical(staged[i])) return fail(c,"PCS residual final polynomial noncanonical");
    }
    // Terminal publication consumes these planes after the final lease has
    // been released. Even a partial free failure leaves output untouched.
    for(auto* id:{&planes.c0,&planes.c1,&planes.c2}) if(residual_retire(c,*id)) return -1;
    std::memcpy(output,staged,size_t(count)*sizeof(*output)); return 0;
}

namespace {
bool contract_session(C71RangeContext* c,uint64_t token) {
    if(!token || !c->contract.active || token!=c->contract.meta || !full(buffer(c,token),C71_PCS_PRIVATE)) {
        fail(c,"PCS contraction capability or phase differs"); return false;
    }
    return true;
}
template<class T> const T* contract_packet(C71RangeContext* c,unsigned span,bool present) {
    if(!present) return nullptr;
    return reinterpret_cast<const T*>(ptr<uint8_t>(c,buffer(c,c->contract.meta))+c->contract.offsets[span]);
}
int contract_band(C71RangeContext* c,uint64_t token,uint64_t weights,const C71PcsResidualPlanes* planes,
    uint64_t start,uint32_t count,const residual::E* left,const residual::E* right) {
    if(!ready(c) || !contract_session(c,token)) return -1;
    auto& s=c->contract;
    const uint64_t length=uint64_t{1}<<(s.shape.remaining-s.kind);
    uintptr_t left_end=0,right_end=0;
    if(start!=s.cursor || !count || count>s.capacity || count>length-start || !left ||
       reinterpret_cast<uintptr_t>(left)%alignof(residual::E) || !c71_dense::span(left,uint64_t(count)*sizeof(*left),left_end) ||
       ((right!=nullptr)!=(s.kind!=0)) || (right && (reinterpret_cast<uintptr_t>(right)%alignof(residual::E) ||
       !c71_dense::span(right,uint64_t(count)*sizeof(*right),right_end))))
        return fail(c,"PCS contraction band order, span or shape");
    for(uint32_t i=0;i<count;++i) if(!residual::canonical(left[i]) || (right && !residual::canonical(right[i])))
        return fail(c,"PCS contraction covector noncanonical");
    residual::ConstPlanes resident_values{};
    Buffer* tile_buffer=nullptr;
    if(planes) {
        if(s.mode==1 || s.shape.dimension>28 || s.shape.dimension-s.shape.remaining>2 ||
           planes->count!=(uint64_t{1}<<s.shape.dimension) || planes->count!=s.shape.live ||
           (s.mode==2 && (s.source[0]!=planes->c0 || s.source[1]!=planes->c1 || s.source[2]!=planes->c2)) ||
           !residual_planes(c,*planes,resident_values)) return fail(c,"PCS contraction resident generation changed");
    } else {
        tile_buffer=buffer(c,weights);
        if(s.mode==2 || !c->stats.weights_sealed || !full(tile_buffer,C71_PCS_WEIGHT_TILES) ||
           tile_buffer->visits!=s.shape.live || s.shape.live!=c->stats.weights_bytes/2 ||
           (s.mode==1 && s.source[0]!=weights)) return fail(c,"PCS contraction sealed W mapping changed");
    }
    auto* band=ptr<residual::E>(c,buffer(c,s.band));
    bool submitted_error=false;
    const uint64_t bytes=uint64_t(count)*sizeof(residual::E);
    if(checked(c,cudaMemcpyAsync(band,left,bytes,cudaMemcpyHostToDevice,c->stream))) submitted_error=true;
    else c->stats.h2d_bytes+=bytes;
    if(!submitted_error && right) {
        if(checked(c,cudaMemcpyAsync(band+s.capacity,right,bytes,cudaMemcpyHostToDevice,c->stream))) submitted_error=true;
        else c->stats.h2d_bytes+=bytes;
    }
    if(!submitted_error) {
        const auto* chunks=contract_packet<residual::Chunk>(c,1,s.shape.equality.chunks!=0);
        const auto* tables=contract_packet<residual::E>(c,2,s.shape.equality.entries!=0);
        auto* output=ptr<residual::E>(c,buffer(c,s.output)); auto* flag=ptr<uint32_t>(c,buffer(c,s.flag));
        const auto status=planes ? c71_pcs_residual_contract_resident_launch(c->stream,resident_values,planes->count,
            s.shape,chunks,tables,s.kind,start,count,band,right?band+s.capacity:nullptr,output,flag) :
            c71_pcs_residual_contract_weights_launch(c->stream,c->weights,c->stats.weights_bytes/2,
                ptr<c71_pcs::WeightTile>(c,tile_buffer),tile_buffer->count,s.shape,chunks,tables,s.kind,start,count,
                band,right?band+s.capacity:nullptr,output,flag);
        if(launched(c,status)) submitted_error=true;
    }
    // Covector storage and each caller-owned host array may be reused only
    // after this same-stream fence, including accepted copies before failure.
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    if(planes) { s.mode=2; s.source[0]=planes->c0; s.source[1]=planes->c1; s.source[2]=planes->c2; }
    else { s.mode=1; s.source[0]=weights; }
    s.cursor+=count; s.visited+=residual::contract_band_visits(s.shape,s.kind,start,count); return 0;
}
}
extern "C" int c71_pcs_residual_contract_begin(C71RangeContext* c,residual::Shape shape,
    const residual::Chunk* chunks,const residual::E* tables,uint32_t kind,uint32_t capacity,uint64_t* token) {
    if(!ready(c)) return -1;
    uintptr_t token_end=0;
    if(!residual_idle(c) || !token || reinterpret_cast<uintptr_t>(token)%8 || !c71_dense::span(token,8,token_end) ||
       !residual::valid(shape,residual::Phase::retention) || kind>1 || shape.remaining<kind ||
       !capacity || capacity>(1u<<21) || capacity>(uint64_t{1}<<(shape.remaining-kind)))
        return fail(c,"PCS contraction begin shape or output");
    const void* arrays[]={&shape,chunks,tables};
    const uint64_t lengths[]={sizeof(shape),uint64_t(shape.equality.chunks)*sizeof(*chunks),uint64_t(shape.equality.entries)*sizeof(*tables)};
    const unsigned alignments[]={alignof(residual::Shape),alignof(residual::Chunk),alignof(residual::E)};
    uint64_t offsets[3]{},bytes=0;
    for(unsigned i=0;i<3;++i) {
        uintptr_t end=0;
        if(lengths[i] && (reinterpret_cast<uintptr_t>(arrays[i])%alignments[i] || !c71_dense::span(arrays[i],lengths[i],end) ||
           c71_dense::overlaps(token,token_end,arrays[i],end))) return fail(c,"PCS contraction packet span or token alias");
        offsets[i]=bytes; bytes+=aligned(lengths[i]);
    }
    if(!residual::valid_packet(shape.equality,chunks,tables)) return fail(c,"PCS contraction prefix packet differs");
    const uint64_t band_bytes=(uint64_t(capacity)<<kind)*sizeof(residual::E);
    const uint64_t required=aligned(bytes)+aligned(band_bytes)+aligned(2*sizeof(residual::E))+aligned(4);
    if(required>c->usable || c->stats.arena_bytes>c->usable-required) return fail(c,"PCS contraction simultaneous arena admission failed");
    *token=0;
    auto& s=c->contract; s.shape=shape; s.kind=kind; s.capacity=capacity; s.active=1;
    std::memcpy(s.offsets,offsets,sizeof(offsets));
    if(allocate(c,C71_PCS_PRIVATE,bytes,&s.meta) || allocate(c,C71_PCS_PRIVATE,band_bytes,&s.band) ||
       allocate(c,C71_PCS_PRIVATE,2*sizeof(residual::E),&s.output) || allocate(c,C71_PCS_PRIVATE,4,&s.flag)) return -1;
    bool submitted_error=false;
    auto* meta=ptr<uint8_t>(c,buffer(c,s.meta));
    for(unsigned i=0;i<3;++i) if(lengths[i]) {
        if(checked(c,cudaMemcpyAsync(meta+offsets[i],arrays[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.h2d_bytes+=lengths[i];
    }
    if(!submitted_error && (residual_zero(c,s.output) || residual_zero(c,s.flag))) submitted_error=true;
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    buffer(c,s.meta)->initialized=buffer(c,s.meta)->count;
    *token=s.meta; return 0;
}
extern "C" int c71_pcs_residual_contract_weights_band(C71RangeContext* c,uint64_t token,uint64_t weights,
    uint64_t start,uint32_t count,const residual::E* left,const residual::E* right) {
    return contract_band(c,token,weights,nullptr,start,count,left,right);
}
extern "C" int c71_pcs_residual_contract_resident_band(C71RangeContext* c,uint64_t token,C71PcsResidualPlanes planes,
    uint64_t start,uint32_t count,const residual::E* left,const residual::E* right) {
    return contract_band(c,token,0,&planes,start,count,left,right);
}
extern "C" int c71_pcs_residual_contract_finish(C71RangeContext* c,uint64_t token,residual::E* output) {
    if(!ready(c) || !contract_session(c,token)) return -1;
    auto& s=c->contract;
    uintptr_t end=0;
    if(!output || reinterpret_cast<uintptr_t>(output)%alignof(residual::E) || !c71_dense::span(output,2*sizeof(*output),end) ||
       !s.mode || s.cursor!=(uint64_t{1}<<(s.shape.remaining-s.kind)) || s.visited!=s.shape.live)
        return fail(c,"PCS contraction finish band coverage or output");
    residual::E staged[2]{}; uint32_t flag=0;
    bool submitted_error=false;
    if(checked(c,cudaMemcpyAsync(staged,ptr<void>(c,buffer(c,s.output)),sizeof(staged),cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
    else c->stats.d2h_bytes+=sizeof(staged);
    if(!submitted_error) {
        if(checked(c,cudaMemcpyAsync(&flag,ptr<void>(c,buffer(c,s.flag)),4,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=4;
    }
    const int synced=fence(c);
    if(submitted_error || synced) return -1;
    if(flag || !residual::canonical(staged[0]) || !residual::canonical(staged[1]) || (!s.kind && !residual::zero(staged[1])))
        return fail(c,"PCS contraction arithmetic or canonicality failed");
    for(auto* id:{&s.flag,&s.output,&s.band,&s.meta}) if(residual_retire(c,*id)) return -1;
    std::memcpy(output,staged,sizeof(staged)); s={}; return 0;
}

namespace {
bool residual_query_session(C71RangeContext* c,uint64_t token) {
    if(!token || !c->residual_query.phase || token!=c->residual_query.meta || !full(buffer(c,token),C71_PCS_PRIVATE)) {
        fail(c,"PCS E query capability or private packet differs"); return false;
    }
    return true;
}
template<class T> const T* residual_query_packet(C71RangeContext* c,unsigned span,bool present) {
    if(!present) return nullptr;
    return reinterpret_cast<const T*>(ptr<uint8_t>(c,buffer(c,c->residual_query.meta))+c->residual_query.offsets[span]);
}
int residual_query_load(C71RangeContext* c,uint64_t token,uint64_t weights,const C71PcsResidualPlanes* planes,c71_pcs::QueryBlock block) {
    if(!ready(c) || !residual_query_session(c,token)) return -1;
    auto& q=c->residual_query;
    const uint64_t n=uint64_t{1}<<(q.shape.remaining-2);
    if(q.phase!=1 || q.loaded || block.first!=q.cursor || block.source_rows!=n+q.pad_rows ||
       block.message_rows!=n || block.active!=n || block.byte_first!=uint64_t(q.column)*n || block.window_first ||
       block.pad_first!=uint64_t(q.column)*q.pad_rows || block.pad_rows!=q.pad_rows || block.pad_only)
        return fail(c,"PCS E query block order, pads or original column differs");
    const auto* chunks=residual_query_packet<residual::Chunk>(c,1,q.shape.equality.chunks!=0);
    const auto* tables=residual_query_packet<residual::E>(c,2,q.shape.equality.entries!=0);
    const auto* pads=residual_query_packet<residual::E>(c,3,true);
    auto* low=ptr<uint64_t>(c,buffer(c,q.low)); auto* flag=ptr<uint32_t>(c,buffer(c,q.flag));
    cudaError_t status=cudaSuccess;
    unsigned attempted=0;
    if(planes) {
        residual::ConstPlanes values{};
        if(q.mode==1 || q.shape.dimension>28 || q.shape.dimension-q.shape.remaining>2 ||
           planes->count!=(uint64_t{1}<<q.shape.dimension) || planes->count!=q.shape.live ||
           (q.mode==2 && (q.source[0]!=planes->c0 || q.source[1]!=planes->c1 || q.source[2]!=planes->c2)) ||
           !residual_planes(c,*planes,values)) return fail(c,"PCS E query resident generation changed");
        status=c71_pcs_residual_query_resident_launch(c->stream,values,planes->count,q.shape,chunks,tables,pads,
            4*q.pad_rows,low,q.capacity,block,flag);
        q.mode=2; q.source[0]=planes->c0; q.source[1]=planes->c1; q.source[2]=planes->c2;
    } else {
        auto* tiles=buffer(c,weights);
        if(q.mode==2 || !c->stats.weights_sealed || !full(tiles,C71_PCS_WEIGHT_TILES) ||
           tiles->visits!=q.shape.live || q.shape.live!=c->stats.weights_bytes/2 ||
           (q.mode==1 && q.source[0]!=weights)) return fail(c,"PCS E query original W mapping changed");
        status=c71_pcs_residual_query_weights_launch(c->stream,c->weights,c->stats.weights_bytes/2,
            ptr<c71_pcs::WeightTile>(c,tiles),tiles->count,q.shape,chunks,tables,pads,4*q.pad_rows,low,q.capacity,block,flag,&attempted);
        q.mode=1; q.source[0]=weights;
    }
    if(planes) { if(launched(c,status)) return -1; }
    else { c->stats.launches+=attempted; if(checked(c,status)) return -1; }
    q.loaded=1; q.mask=0; return 0;
}
}
extern "C" int c71_pcs_residual_query_begin(C71RangeContext* c,residual::Shape shape,const residual::Chunk* chunks,
    const residual::E* tables,const residual::E* pads,uint32_t pad_count,uint32_t capacity,uint32_t column,uint64_t* token) {
    if(!ready(c)) return -1;
    uintptr_t token_end=0;
    if(!residual_idle(c) || !token || reinterpret_cast<uintptr_t>(token)%8 || !c71_dense::span(token,8,token_end) ||
       !residual::valid(shape,residual::Phase::retention) || shape.remaining<2 || shape.remaining>29 ||
       !power2(capacity) || capacity>(1u<<20) || column>=4 || !pad_count || pad_count%4 || pad_count>4*1536 || !pads)
        return fail(c,"PCS E query begin shape, capacity, column or output");
    const void* arrays[]={&shape,chunks,tables,pads};
    const uint64_t lengths[]={sizeof(shape),uint64_t(shape.equality.chunks)*sizeof(*chunks),
        uint64_t(shape.equality.entries)*sizeof(*tables),uint64_t(pad_count)*sizeof(*pads)};
    const unsigned alignments[]={alignof(residual::Shape),alignof(residual::Chunk),alignof(residual::E),alignof(residual::E)};
    uint64_t offsets[4]{},bytes=0;
    for(unsigned i=0;i<4;++i) {
        uintptr_t end=0;
        if(lengths[i] && (reinterpret_cast<uintptr_t>(arrays[i])%alignments[i] || !c71_dense::span(arrays[i],lengths[i],end) ||
           c71_dense::overlaps(token,token_end,arrays[i],end))) return fail(c,"PCS E query packet span, alignment or token alias");
        offsets[i]=bytes; bytes+=aligned(lengths[i]);
    }
    if(!residual::valid_packet(shape.equality,chunks,tables)) return fail(c,"PCS E query equality packet differs");
    for(uint32_t i=0;i<pad_count;++i) if(!residual::canonical(pads[i])) return fail(c,"PCS E query pad noncanonical");
    const uint64_t required=aligned(bytes)+aligned(uint64_t(capacity)*24)+aligned(4);
    if(required>c->usable || c->stats.arena_bytes>c->usable-required) return fail(c,"PCS E query simultaneous arena admission failed");
    *token=0;
    auto& q=c->residual_query; q.shape=shape; q.capacity=capacity; q.column=column; q.pad_rows=pad_count/4; q.phase=1;
    const uint64_t source_rows=(uint64_t{1}<<(shape.remaining-2))+q.pad_rows;
    q.cursor=((source_rows+capacity-1)/capacity-1)*capacity;
    std::memcpy(q.offsets,offsets,sizeof(offsets));
    if(allocate(c,C71_PCS_PRIVATE,bytes,&q.meta) || allocate(c,C71_PCS_PRIVATE,uint64_t(capacity)*24,&q.low) ||
       allocate(c,C71_PCS_PRIVATE,4,&q.flag)) return -1;
    bool submitted_error=false;
    auto* meta=ptr<uint8_t>(c,buffer(c,q.meta));
    for(unsigned i=0;i<4;++i) if(lengths[i]) {
        if(checked(c,cudaMemcpyAsync(meta+offsets[i],arrays[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.h2d_bytes+=lengths[i];
    }
    if(!submitted_error && residual_zero(c,q.flag)) submitted_error=true;
    const int synced=fence(c); // all consumer packet pointers may now be retired
    if(submitted_error || synced) return -1;
    buffer(c,q.meta)->initialized=buffer(c,q.meta)->count;
    *token=q.meta; return 0;
}
extern "C" int c71_pcs_residual_query_weights(C71RangeContext* c,uint64_t token,uint64_t tiles,c71_pcs::QueryBlock block) {
    return residual_query_load(c,token,tiles,nullptr,block);
}
extern "C" int c71_pcs_residual_query_resident(C71RangeContext* c,uint64_t token,C71PcsResidualPlanes planes,c71_pcs::QueryBlock block) {
    return residual_query_load(c,token,0,&planes,block);
}
extern "C" int c71_pcs_residual_query_root(C71RangeContext* c,uint64_t token,uint32_t limb,uint64_t high,
    uint64_t inverse,uint64_t modulus,uint64_t forward,uint64_t backward,uint64_t work,uint64_t scratch,uint64_t output) {
    if(!ready(c) || !residual_query_session(c,token)) return -1;
    auto& q=c->residual_query;
    auto* h=high?buffer(c,high):nullptr; auto* i=buffer(c,inverse); auto* m=buffer(c,modulus);
    auto* f=buffer(c,forward); auto* b=buffer(c,backward); auto* w=buffer(c,work); auto* s=buffer(c,scratch); auto* o=buffer(c,output);
    if(q.phase!=1 || !q.loaded || limb>=3 || (q.mask&(1u<<limb)) || high!=q.last[limb] ||
       (high && (!full(h,C71_PCS_BASE) || h->count!=q.capacity || h->residual_group!=q.meta || h->residual_role!=3+limb)) ||
       !full(i,C71_PCS_BASE) || !full(m,C71_PCS_BASE) || i==m || i->count!=2*q.capacity || m->count!=2*q.capacity ||
       !query_twiddles(f,2*q.capacity,0) || !query_twiddles(b,2*q.capacity,1) ||
       !query_output(w,2*q.capacity) || !query_output(s,2*q.capacity) || !query_output(o,q.capacity) || w==s || w==o || s==o)
        return fail(c,"PCS E query root order, lineage, factors or workspace differs");
    for(auto* read:{h,i,m,f,b}) if(read && (read==w || read==s || read==o)) return fail(c,"PCS E query root output alias");
    for(unsigned other=0;other<3;++other) if(other!=limb && output==q.last[other])
        return fail(c,"PCS E query root overwrites another limb");
    const auto* low=ptr<uint64_t>(c,buffer(c,q.low))+uint64_t(limb)*q.capacity;
    if(!high) {
        const uint64_t bytes=uint64_t(q.capacity)*8;
        // The first block has degree < capacity: its remainder is itself.
        if(checked(c,cudaMemcpyAsync(ptr<void>(c,o),low,bytes,cudaMemcpyDeviceToDevice,c->stream))) return -1;
        c->stats.d2d_bytes+=bytes;
    } else {
        unsigned attempted=0; uint64_t copied=0;
        const auto status=c71_pcs_query_remainder_launch(c->stream,ptr<uint64_t>(c,h),low,ptr<uint64_t>(c,i),ptr<uint64_t>(c,m),
            ptr<uint64_t>(c,f),ptr<uint64_t>(c,b),ptr<uint64_t>(c,w),ptr<uint64_t>(c,s),ptr<uint64_t>(c,o),
            q.capacity,q.capacity,0,&attempted,&copied);
        c->stats.launches+=attempted; c->stats.d2d_bytes+=copied;
        if(checked(c,status)) return -1;
    }
    o->initialized=o->count; o->residual_group=q.meta; o->residual_role=3+limb; o->visits=q.capacity;
    q.last[limb]=output; q.mask|=1u<<limb;
    if(q.mask==7) { q.loaded=0; if(q.cursor) q.cursor-=q.capacity; else q.phase=2; }
    return 0;
}
extern "C" int c71_pcs_residual_query_finish(C71RangeContext* c,uint64_t token,const uint64_t final_columns[3],
    uint32_t count,uint64_t* output) {
    if(!ready(c) || !residual_query_session(c,token)) return -1;
    auto& q=c->residual_query;
    uintptr_t ids_end=0,output_end=0;
    if(q.phase!=2 || q.loaded || q.mask!=7 || !final_columns || reinterpret_cast<uintptr_t>(final_columns)%8 ||
       !c71_dense::span(final_columns,24,ids_end) || !count || count>q.capacity || !output || reinterpret_cast<uintptr_t>(output)%8 ||
       !c71_dense::span(output,uint64_t(count)*24,output_end) || c71_dense::overlaps(final_columns,ids_end,output,output_end))
        return fail(c,"PCS E query finish coverage or output span");
    Buffer* finals[3]{};
    for(unsigned limb=0;limb<3;++limb) {
        finals[limb]=buffer(c,final_columns[limb]);
        if(!full(finals[limb],C71_PCS_BASE) || finals[limb]->count!=q.capacity || finals[limb]->residual_group!=q.meta ||
           finals[limb]->residual_role!=3+limb || finals[limb]->visits!=1 || final_columns[limb]!=q.last[limb])
            return fail(c,"PCS E query final column lineage differs");
    }
    const uint64_t bytes=uint64_t(count)*24;
    if(c->account && c->account(int64_t(bytes))) return fail(c,"PCS E query host publication budget exhausted");
    auto* staged=new(std::nothrow) uint64_t[uint64_t(count)*3];
    if(!staged) { if(c->account) c->account(-int64_t(bytes)); return fail(c,"PCS E query host staging unavailable"); }
    c->stats.host_owner_bytes+=bytes;
    const auto cleanup=[&](int status) {
        delete[] staged;
        c->stats.host_owner_bytes-=bytes;
        if(c->account) c->account(-int64_t(bytes));
        return status;
    };
    bool submitted_error=false;
    for(unsigned limb=0;limb<3;++limb) {
        if(checked(c,cudaMemcpyAsync(staged+uint64_t(limb)*count,ptr<void>(c,finals[limb]),uint64_t(count)*8,cudaMemcpyDeviceToHost,c->stream))) {
            submitted_error=true; break;
        }
        c->stats.d2h_bytes+=uint64_t(count)*8;
    }
    uint32_t flag=0;
    if(!submitted_error) {
        if(checked(c,cudaMemcpyAsync(&flag,ptr<void>(c,buffer(c,q.flag)),4,cudaMemcpyDeviceToHost,c->stream))) submitted_error=true;
        else c->stats.d2h_bytes+=4;
    }
    const int synced=fence(c);
    if(submitted_error || synced) return cleanup(-1);
    if(flag) return cleanup(fail(c,"PCS E query original/retained/pad arithmetic failed"));
    for(uint64_t i=0;i<uint64_t(count)*3;++i) if(staged[i]>=P) return cleanup(fail(c,"PCS E query final column noncanonical"));
    for(auto* id:{&q.flag,&q.low,&q.meta}) if(residual_retire(c,*id)) return cleanup(-1);
    std::memcpy(output,staged,size_t(bytes)); q={}; return cleanup(0);
}

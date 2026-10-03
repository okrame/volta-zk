// Tests the real owner with a deferred fake driver, NOT GPU math/execution.
#include "c71_range_runtime.h"
#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
using namespace c71_range;
struct FakeStream { std::vector<std::function<void()>> pending; };
static bool fail_launch=false, fail_fence=false, fail_free=false, corrupt=false;
static unsigned allocations=0, frees=0, launches=0;
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
cudaError_t cudaFree(void* p) {
    ++frees; delete[] static_cast<unsigned char*>(p); return fail_free?1:0;
}
cudaError_t cudaMemcpyAsync(void* d,const void* s,size_t n,cudaMemcpyKind kind,cudaStream_t stream) {
    stream->pending.push_back([=] { std::memcpy(d,s,n); if(kind==cudaMemcpyDeviceToHost && corrupt) *static_cast<uint64_t*>(d)=P; });
    return 0;
}
cudaError_t cudaMemsetAsync(void* p,int x,size_t n,cudaStream_t s) {
    s->pending.push_back([=] { std::memset(p,x,n); }); return 0;
}
const char* cudaGetErrorString(cudaError_t) { return "injected CUDA failure"; }
static int launch(cudaStream_t s,void* p,size_t n) {
    ++launches; if(fail_launch) return 1;
    s->pending.push_back([=] { std::memset(p,0,n); }); return 0;
}
extern "C" int c71_range_launch_roots(cudaStream_t s,unsigned,const void*,size_t,unsigned,Fp3,Pair* p,size_t n) { return launch(s,p,n*sizeof(*p)); }
extern "C" int c71_range_launch_groups(cudaStream_t s,unsigned,const void*,size_t words,Group g,Children* p,size_t,Fp3* h,size_t n) {
    return g.width?launch(s,h,n*sizeof(*h)):launch(s,p+g.first_tail,(words>>(g.bottom+g.prefix_bits))*sizeof(*p));
}
extern "C" int c71_range_launch_canopy(cudaStream_t s,const Pair*,Pair* p,size_t n) { return launch(s,p,n*sizeof(*p)); }
extern "C" int c71_range_launch_h_sum(cudaStream_t s,const Fp3*,Fp3* p,unsigned n,unsigned) { return launch(s,p,n*sizeof(*p)); }
extern "C" int c71_range_launch_h_fold(cudaStream_t s,const Fp3*,Fp3* p,unsigned n,Fp3) { return launch(s,p,n*n*sizeof(*p)); }
extern "C" int c71_range_launch_child_fold(cudaStream_t s,Children* p,size_t n,Fp3) { return launch(s,p,n*sizeof(*p)); }
extern "C" int c71_range_launch_coefficients(cudaStream_t s,const Children*,size_t half,Round,Cubic* p) { return launch(s,p,((half+255)/256)*sizeof(*p)); }
extern "C" int c71_range_launch_reduce(cudaStream_t s,const Cubic*,size_t n,Cubic* p) { return launch(s,p,((n+255)/256)*sizeof(*p)); }
extern "C" int c71_range_launch_h_coefficients(cudaStream_t s,const Fp3*,unsigned,Round,Cubic* p) { return launch(s,p,sizeof(*p)); }

static C71RangeContext* create(uint64_t bytes=262144) {
    C71RangeContext* c=nullptr; assert(!c71_range_create(0,bytes,256,&c)); return c;
}
static uint64_t alloc(C71RangeContext* c,unsigned kind,uint64_t n) {
    uint64_t id=0; assert(!c71_range_alloc(c,kind,n,&id)); return id;
}
static C71RangeStats stats(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_stats(c,&s)); return s; }
static void close(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_close(c,&s)); assert(!s.arena_bytes && !s.cleanup_failed); }
static uint64_t roots(C71RangeContext* c,unsigned kind=0,unsigned n=2048) {
    const auto in=alloc(c,kind,2*n), out=alloc(c,C71_PAIR,n);
    std::vector<int16_t> data(2*n,3);
    assert(!c71_range_upload(c,in,data.data(),2*n*(kind+1)));
    assert(!c71_range_roots(c,in,1,{5,2,3},out,0));
    assert(!c71_range_release(c,in)); return out;
}
int main() {
    C71RangeContext* c=nullptr;
    assert(c71_range_runtime_abi()==1);
    assert(c71_range_create(0,6442451200ULL,256,&c) && !c && !allocations);
    assert(c71_range_create(0,512,512,&c) && !c && !allocations);
    assert(c71_range_create(1,512,256,&c) && c);
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
    after=stats(c); assert(!after.live_capacity_bytes && after.arena_bytes==262144 && !frees);
    close(c); assert(allocations==1 && frees==1);

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
    c=create(); fail_free=true;
    assert(c71_range_close(c,&final) && final.cleanup_failed && final.arena_bytes==262144);
    fail_free=false;
    assert(allocations==frees);
    std::puts("C71_RANGE_OWNER_HOST {\"rejections\":13,\"max_arena_bytes\":262144,\"gpu_execution\":false,\"credit\":false}");
}

// Same reduced sequence before/after; deferred driver, no CUDA timing credit.
#include "c71_range_runtime.h"
#include <cassert>
#include <cstdio>
#include <vector>
int main() {
    C71RangeContext* owner=nullptr;
    assert(!c71_range_create(0,262144,256,nullptr,&owner));
    C71RangeStats before{},after{},final{};
    assert(!c71_range_stats(owner,&before));
    uint64_t output_bytes=0;
    for(uint64_t count: {1,3,8,255,256,257,16006}) {
        uint64_t raw=0;
        assert(!c71_range_alloc(owner,C71_I64,count,&raw));
        assert(!c71_dense_pointwise(owner,0,0,0,0,{0,0,0},raw));
        std::vector<int64_t> actual(count,-1);
        assert(!c71_original_read(owner,raw,C71_I64,0,count,actual.data()));
        for(auto value:actual) assert(value==0);
        assert(!c71_range_release(owner,raw));
        output_bytes+=8*count;
    }
    assert(!c71_range_stats(owner,&after));
    assert(!c71_range_close(owner,&final) && !final.cleanup_failed && !final.arena_bytes);
    std::printf("C71_PUBLIC_ZERO_COMPARISON {\"operations\":7,\"output_write_bytes\":%llu,\"allocations\":%llu,\"releases_before_close\":%llu,\"retained_device_bytes\":%llu,\"host_owner_bytes\":%llu,\"application_kernel_launches\":%llu,\"fences_including_observation_and_release\":%llu,\"d2h_bytes_including_observation\":%llu,\"memset_api_bytes\":%llu,\"gpu_execution\":false,\"credit\":false}\n",
        (unsigned long long)output_bytes,
        (unsigned long long)(after.allocations-before.allocations),
        (unsigned long long)(after.releases-before.releases),
        (unsigned long long)after.arena_bytes,(unsigned long long)after.host_owner_bytes,
        (unsigned long long)(after.launches-before.launches),
        (unsigned long long)(after.fences-before.fences),
        (unsigned long long)(after.d2h_bytes-before.d2h_bytes),
        (unsigned long long)(after.zeroed_bytes-before.zeroed_bytes));
}

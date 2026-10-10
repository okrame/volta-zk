// Reduced original math through the common owner and deferred fake driver.
#include "c71_range_runtime.h"
#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
    C71RangeContext* owner=nullptr;
    assert(!c71_range_create(0,262144,256,nullptr,&owner));
    uint64_t input=0;
    const int16_t values[]={1,2,3,4,-1,-2,-3,-4};
    assert(!c71_range_alloc(owner,C71_I16,8,&input));
    assert(!c71_range_upload(owner,input,values,sizeof(values)));
    C71RangeStats before{},after{},final{};
    assert(!c71_range_stats(owner,&before));
    for(unsigned operation=0;operation<32;++operation) {
        uint64_t raw=0;
        assert(!c71_range_alloc(owner,C71_I64,8,&raw));
        assert(!c71_dense_pointwise(owner,input,0,0,0,{2,0,0},raw));
        int64_t actual[8]{};
        const int64_t expected[]={2,4,6,8,-2,-4,-6,-8};
        assert(!c71_original_read(owner,raw,C71_I64,0,8,actual));
        assert(!std::memcmp(actual,expected,sizeof(expected)));
        assert(!c71_range_release(owner,raw));
    }
    assert(!c71_range_stats(owner,&after));
    assert(!c71_range_release(owner,input));
    C71RangeStats retained{};
    assert(!c71_range_stats(owner,&retained));
    assert(!c71_range_close(owner,&final) && !final.cleanup_failed && !final.arena_bytes);
    std::printf("C71_FLAG_COUNTER_COMPARISON {\"numeric_operations\":32,\"flag_allocations\":%llu,\"flag_releases_before_close\":%llu,\"retained_device_bytes_before_close\":%llu,\"host_owner_bytes\":%llu,\"launches\":%llu,\"fences_including_observation_and_output_release\":%llu,\"d2h_bytes_including_observation\":%llu,\"flag_zeroed_bytes\":%llu,\"gpu_execution\":false,\"credit\":false}\n",
        (unsigned long long)(after.allocations-before.allocations-32),
        (unsigned long long)(after.releases-before.releases-32),
        (unsigned long long)retained.arena_bytes,(unsigned long long)retained.host_owner_bytes,
        (unsigned long long)(after.launches-before.launches),
        (unsigned long long)(after.fences-before.fences),
        (unsigned long long)(after.d2h_bytes-before.d2h_bytes),
        (unsigned long long)(after.zeroed_bytes-before.zeroed_bytes));
}

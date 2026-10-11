// Explicit allocator experiment with a deferred fake driver; no GPU credit.
#define main archived_range_host_main
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#include "c71_range_runtime_host.cpp"
#pragma GCC diagnostic pop
#undef main
#include <string>

int main(int argc,char** argv) {
    assert(argc==2);
    const std::string scenario=argv[1];
    constexpr uint64_t reserve=128ULL<<20, capacity=1ULL<<20;
    joint_limit=scenario=="reserve_failure"?2ULL<<20:reserve+(2ULL<<20);
    C71RangeContext* context=nullptr;
    const int created=c71_range_create(0,2ULL<<20,256,joint_account,&context);
    assert(context && (created!=0)==(scenario=="reserve_failure"));
    const auto initial=stats(context);
    assert(initial.host_owner_bytes==42160);
    if(!created) {
        assert(joint_live==initial.host_owner_bytes+reserve);
        if(scenario=="allocation_failure") fail_pool_alloc=true;
        if(scenario=="cache_limit") fake_pool_reserved_extra=129ULL<<20;
        uint64_t id=0;
        const int allocated=c71_range_alloc(context,C71_I64,capacity/8,&id);
        assert((allocated!=0)==(scenario=="allocation_failure" || scenario=="cache_limit"));
        if(!allocated) {
            assert(joint_live==initial.host_owner_bytes+reserve+capacity);
            if(scenario=="normal") {
                assert(!c71_dense_pointwise(context,0,0,0,0,{0,0,0},id));
                int64_t word=-1;
                assert(!c71_original_read(context,id,C71_I64,0,1,&word) && !word);
                const auto before=stats(context);
                assert(!c71_range_release(context,id));
                assert(stats(context).fences==before.fences+2);
            } else if(scenario=="query_failure") fail_pool_query=true;
            else if(scenario=="free_failure" || scenario=="free_fence_failure") {
                fail_pool_free=scenario=="free_failure";
                fail_pool_free_fence=scenario=="free_fence_failure";
                assert(c71_range_release(context,id));
            }
            else if(scenario=="trim_failure") {
                fail_pool_trim=true;
                assert(c71_range_release(context,id));
            } else if(scenario=="fence_failure") fail_fence=true;
            else assert(false);
        }
    }
    C71RangeStats final{};
    const int closed=c71_range_close(context,&final);
    const bool cleanup_error=scenario=="query_failure" || scenario=="trim_failure" ||
        scenario=="fence_failure" || scenario=="cache_limit" ||
        scenario=="free_failure" || scenario=="free_fence_failure";
    assert((closed!=0)==cleanup_error);
    const uint64_t buffer_debt=(scenario=="trim_failure" || scenario=="fence_failure" ||
        scenario=="free_failure" || scenario=="free_fence_failure")?capacity:0;
    const uint64_t cache_debt=(buffer_debt || scenario=="query_failure")?reserve:0;
    assert(final.arena_bytes==buffer_debt && joint_live==buffer_debt+cache_debt);
    if(scenario=="trim_failure") assert(frees==1);
    if(scenario=="fence_failure") assert(frees==0);
    if(scenario=="query_failure") assert(frees==1);
    if(scenario=="free_failure") assert(frees==0);
    if(scenario=="free_fence_failure") assert(frees==1);
    std::printf("C71_ASYNC_ALLOCATOR_HOST {\"scenario\":\"%s\",\"owner_bytes\":%llu,\"fixed_cache_reserve_bytes\":%llu,\"final_joint_debt_bytes\":%llu,\"allocations\":%u,\"frees\":%u,\"gpu_execution\":false,\"credit\":false}\n",
        scenario.c_str(),(unsigned long long)initial.host_owner_bytes,(unsigned long long)reserve,
        (unsigned long long)joint_live,allocations,frees);
}

// Diagnostic lifecycle tests with a deferred driver; no CUDA execution.
#define main archived_range_host_main
#define cudaMalloc underlying_cudaMalloc
#define cudaFree underlying_cudaFree
#define cudaStreamSynchronize underlying_cudaStreamSynchronize
#define cudaSetDevice underlying_cudaSetDevice
// The archived main's implicit return is valid only while named main. This
// renamed entry is retained for linking its driver and is never invoked.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#include "c71_range_runtime_host.cpp"
#pragma GCC diagnostic pop
#undef cudaSetDevice
#undef cudaStreamSynchronize
#undef cudaFree
#undef cudaMalloc
#undef main
#include "c71_owner_trace.h"
#include <string>

// Only this test executable links --wrap=write. Select pre-events by public
// operation/edge, without changing the production logger or CUDA runtime.
static const char* fail_before_operation=nullptr;
static void poison_trace_descriptor() {
    const char* path=std::getenv("C71_OWNER_TRACE_PATH");
    assert(path);
    int found=-1;
    for(int descriptor=3;descriptor<256;++descriptor) {
        char link[64], target[c71_owner_trace::Trace::max_path_bytes];
        std::snprintf(link,sizeof(link),"/proc/self/fd/%d",descriptor);
        const auto length=::readlink(link,target,sizeof(target)-1);
        if(length<0) continue;
        target[length]='\0';
        if(!std::strcmp(target,path)) { assert(found<0); found=descriptor; }
    }
    assert(found>=0);
    const int full=::open("/dev/full",O_WRONLY|O_CLOEXEC);
    assert(full>=0 && ::dup2(full,found)==found && !::close(full));
}
extern "C" ssize_t __real_write(int,const void*,size_t);
extern "C" ssize_t __wrap_write(int descriptor,const void* input,size_t count) {
    if(fail_before_operation && count<c71_owner_trace::Trace::record_bytes) {
        char record[c71_owner_trace::Trace::record_bytes];
        std::memcpy(record,input,count); record[count]='\0';
        char operation[96];
        std::snprintf(operation,sizeof(operation),"\"op\":\"%s\"",fail_before_operation);
        if(std::strstr(record,operation) && std::strstr(record,"\"edge\":\"before\"")) {
            fail_before_operation=nullptr;
            poison_trace_descriptor();
        }
    }
    return __real_write(descriptor,input,count);
}

enum class Fault { none, post_alloc, post_free, post_fence };
static Fault armed=Fault::none;
static unsigned set_device_calls=0, native_fences=0;
static void* failed_free_pointer=nullptr;
static unsigned failed_free_attempts=0;
cudaError_t cudaSetDevice(int device) { ++set_device_calls; return underlying_cudaSetDevice(device); }
cudaError_t cudaMalloc(void** output,size_t bytes) {
    const auto status=underlying_cudaMalloc(output,bytes);
    if(armed==Fault::post_alloc) { armed=Fault::none; poison_trace_descriptor(); }
    return status;
}
cudaError_t cudaFree(void* allocation) {
    if(allocation==failed_free_pointer) ++failed_free_attempts;
    const auto status=underlying_cudaFree(allocation);
    if(armed==Fault::post_free) { armed=Fault::none; poison_trace_descriptor(); }
    return status;
}
cudaError_t cudaStreamSynchronize(cudaStream_t stream) {
    ++native_fences;
    const auto status=underlying_cudaStreamSynchronize(stream);
    if(armed==Fault::post_fence) { armed=Fault::none; poison_trace_descriptor(); }
    return status;
}
static void assert_no_publication(C71RangeContext* context,uint64_t output) {
    int64_t untouched=123;
    assert(c71_original_read(context,output,C71_I64,0,1,&untouched) && untouched==123);
    const auto before=stats(context);
    assert(c71_dense_pointwise(context,0,0,0,0,{0,0,0},output));
    assert(stats(context).launches==before.launches && stats(context).fences==before.fences);
}
int main(int argc,char** argv) {
    assert(argc==2 && !joint_live);
    const std::string scenario=argv[1];
    if(scenario=="large") joint_limit=2ULL<<20;
    C71RangeContext* context=nullptr;
    if(scenario=="no_env") assert(!::unsetenv("C71_OWNER_TRACE_PATH"));
    const bool init_failure=scenario=="no_env" || scenario=="existing";
    const int created=c71_range_create(0,scenario=="large"?(2ULL<<20):262144,256,joint_account,&context);
    assert(context && (created!=0)==init_failure);
    const auto initial=stats(context);
    assert(initial.host_owner_bytes==42128 && joint_live==initial.host_owner_bytes);
    if(init_failure) {
        assert(initial.stopped && !set_device_calls && !allocations && !frees && !launches);
    } else if(scenario=="windowmatched" || scenario=="windowmissing") {
        install(context);
        const uint32_t first_coset=scenario=="windowmatched"?4:0;
        const c71_pcs::SourceShape shape{4,4,4,1,16,first_coset};
        const auto low=alloc(context,C71_PCS_POWERS,16), high=alloc(context,C71_PCS_POWERS,8);
        const auto first=alloc(context,C71_PCS_SOURCE_PENDING,1024), second=alloc(context,C71_PCS_SOURCE_PENDING,1024);
        assert(stats(context).arena_bytes==16896 && joint_live==initial.host_owner_bytes+16896);
        assert(!c71_pcs_source_powers(context,low,high,shape));
        assert(!c71_pcs_source_begin(context,first,second,low,high,0,shape));
        assert(stats(context).arena_bytes==17152 && joint_live==initial.host_owner_bytes+17152);
        // Pending outputs remain private; close must drain powers and memsets
        // before freeing every capacity, even if the target group was absent.
    } else if(scenario=="large") {
        install(context);
        const auto big=alloc(context,C71_I64,1<<17), small=alloc(context,C71_I64,3);
        assert(!c71_dense_pointwise(context,0,0,0,0,{0,0,0},big));
        assert(!c71_dense_pointwise(context,0,0,0,0,{0,0,0},small));
        int64_t words[]={-1,-1,-1};
        assert(!c71_original_read(context,small,C71_I64,0,3,words));
        for(auto value:words) assert(value==0);
        assert(!c71_range_release(context,big) && !c71_range_release(context,small));
        assert(stats(context).arena_bytes==256);
    } else if(scenario=="prealloc" || scenario=="postalloc") {
        if(scenario=="prealloc") fail_before_operation="allocate";
        else armed=Fault::post_alloc;
        uint64_t output=0;
        assert(c71_range_alloc(context,C71_I64,3,&output));
        const auto stopped=stats(context);
        assert(stopped.stopped && stopped.allocations==(scenario=="postalloc"?1u:0u));
        assert(stopped.arena_bytes==(scenario=="postalloc"?256u:0u));
        assert(joint_live==initial.host_owner_bytes+stopped.arena_bytes);
        assert(allocations==stopped.allocations && !frees && !launches);
        assert_no_publication(context,output);
    } else {
        install(context); // W is global/exempt; its separate bytes stay visible.
        assert(stats(context).weights_bytes==20 && joint_live==initial.host_owner_bytes);
        const auto output=alloc(context,C71_I64,3);
        void* const output_allocation=last_allocation;
        if(scenario=="postfence") armed=Fault::post_fence;
        const int produced=c71_dense_pointwise(context,0,0,0,0,{0,0,0},output);
        if(scenario=="postfence") {
            assert(produced && stats(context).stopped && stats(context).arena_bytes==512);
            assert_no_publication(context,output);
        } else {
            assert(!produced);
            if(scenario=="normal") {
                const auto quantized=alloc(context,C71_I16,3);
                assert(!c71_dense_quantize(context,output,0,quantized));
                int16_t actual[]={-1,-1,-1};
                assert(!c71_original_read(context,quantized,C71_I16,0,3,actual));
                for(auto value:actual) assert(value==0);
                assert(joint_live==initial.host_owner_bytes+768);
                assert(!c71_range_release(context,output) && !c71_range_release(context,quantized));
                assert(stats(context).arena_bytes==256 && joint_live==initial.host_owner_bytes+256);
            } else {
                const auto before=stats(context);
                const auto free_before=frees;
                if(scenario=="prefree") fail_before_operation="c71_range_release";
                else if(scenario=="postfree") armed=Fault::post_free;
                else {
                    assert(scenario=="free_failure" || scenario=="free_failure_trace");
                    failed_free_pointer=output_allocation;
                    fail_free=true;
                }
                assert(c71_range_release(context,output));
                fail_free=false;
                const auto stopped=stats(context);
                assert(stopped.stopped);
                const bool freed=scenario=="postfree";
                assert(stopped.releases==before.releases+(freed?1u:0u));
                assert(stopped.arena_bytes==before.arena_bytes-(freed?256u:0u));
                assert(frees==free_before+(scenario=="prefree"?0u:1u));
                if(failed_free_pointer) assert(failed_free_attempts==1);
                assert(joint_live==initial.host_owner_bytes+stopped.arena_bytes);
                assert_no_publication(context,output);
                if(scenario=="free_failure_trace") poison_trace_descriptor();
            }
        }
    }
    const auto before_close=stats(context);
    const auto frees_before_close=frees, fences_before_close=native_fences;
    const bool original_free_failure=scenario=="free_failure" || scenario=="free_failure_trace";
    const uint64_t debt=original_free_failure?256:0;
    C71RangeStats final{};
    const int closed=c71_range_close(context,&final);
    const bool cleanup_error=scenario!="normal" && scenario!="windowmatched" && scenario!="large";
    assert((closed!=0)==cleanup_error);
    assert(final.cleanup_failed==cleanup_error);
    assert(final.arena_bytes==debt && !final.weights_bytes && joint_live==debt);
    assert(final.allocations==final.releases+(original_free_failure?1u:0u));
    const unsigned expected_frees=unsigned(before_close.allocations-before_close.releases)-unsigned(original_free_failure)+(before_close.weights_bytes?1u:0u);
    assert(frees==frees_before_close+expected_frees);
    if(original_free_failure) assert(failed_free_attempts==1);
    if(!init_failure) assert(native_fences==fences_before_close+1);
    std::printf("C71_OWNER_TRACE_RUNTIME {\"scenario\":\"%s\",\"host_owner_bytes\":%llu,\"final_arena_bytes\":%llu,\"joint_debt_bytes\":%llu,\"allocations\":%llu,\"releases\":%llu,\"native_allocations\":%u,\"native_frees\":%u,\"native_fences\":%u,\"cleanup_failed\":%s,\"gpu_execution\":false,\"credit\":false}\n",
        scenario.c_str(),(unsigned long long)initial.host_owner_bytes,(unsigned long long)final.arena_bytes,
        (unsigned long long)joint_live,(unsigned long long)final.allocations,(unsigned long long)final.releases,
        allocations,frees,native_fences,final.cleanup_failed?"true":"false");
}

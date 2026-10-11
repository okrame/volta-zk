#define main c71_other_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main

int main() {
    using namespace c71_rms_prefix;
    for(unsigned fault=0;fault<=32;++fault) {
        assert(!joint_live);joint_limit=16ULL<<20;
        C71RangeContext* c=nullptr;assert(!c71_range_create(0,16ULL<<20,256,joint_account,&c));
        Gate gate{0,2,3,0,{1,0,0}};GateRange range{0,1};Fp3 previous[8]{},selector[1]{};
        Fp3 challenges[8]{},output[6];uint64_t token=0;
        auto untouched=[&] {for(auto& x:output)x={17,19,23};};untouched();
        if(fault==4)range.first=1;
        if(fault==5)gate.reserved=1;
        if(fault==6)gate.y=8;
        if(fault==7)gate.weight.c0=P;
        if(fault==8)previous[0].c0=P;
        if(fault==9)selector[0].c0=P;
        if(fault==11)joint_limit=joint_live;
        if(fault==12)upload_fail_after=0;
        if(fault==13)fail_fence=true;
        if(fault==14)fail_launch=true;
        if(fault==32)fail_memset=true;
        int status=c71_rms_index_begin(c,fault==1?3:8,fault==2?0:1,fault==3?0:1,&gate,&range,previous,selector,
            fault==10?reinterpret_cast<uint64_t*>(&gate):&token);
        joint_limit=16ULL<<20;upload_fail_after=-1;fail_launch=false;fail_memset=false;
        if((fault<=14 && fault) || fault==32)assert(status);
        else {
            assert(!status && token && stats(c).allocations==3);
            if(fault==20)download_fail_after=0;
            if(fault==21)fail_fence=true;
            if(fault==22)fail_launch=true;
            if(fault==27)joint_limit=joint_live;
            if(fault==31)corrupt=true;
            if(fault==25)status=c71_original_read(c,token,0,0,1,output);
            else if(fault==26)status=c71_rms_index_begin(c,8,1,1,&gate,&range,previous,selector,&token);
            else status=c71_rms_index_step(c,fault==16?token+1000:token,
                fault==15 || fault==29 || fault==30?challenges:nullptr,
                fault==15?1:(fault==29?7:0),fault==28?nullptr:output);
            joint_limit=16ULL<<20;download_fail_after=-1;fail_launch=false;corrupt=false;
            if(fault>=15 && fault!=17 && fault!=18 && fault!=19 && fault!=23 && fault!=24)assert(status);
            else {
                if(status)std::fprintf(stderr,"index fault=%u: %s\n",fault,c71_range_error(c));
                assert(!status);untouched();
                if(fault==24)status=c71_rms_index_step(c,token,nullptr,0,output);
                else {
                    if(fault==17)challenges[0].c0=P;
                    status=c71_rms_index_step(c,token,challenges,1,fault==19?challenges:output);
                    if(fault==18) {
                        assert(!status);untouched();challenges[0].c0=1;
                        status=c71_rms_index_step(c,token,challenges,2,output);
                    }else if(!fault || fault==23) {
                        assert(!status);
                        for(unsigned round=2;round<6;++round)assert(!c71_rms_index_step(c,token,challenges,round,output));
                        untouched();if(fault==23)fail_free=true;
                        status=c71_rms_index_step(c,token,challenges,6,output);fail_free=false;
                    }
                }
                if(fault)assert(status);
                else {assert(!status && !stats(c).arena_bytes && stats(c).host_owner_bytes==42496);
                    for(auto x:output)assert(!x.c0 && !x.c1 && !x.c2);}
            }
        }
        if(fault) {assert(stats(c).stopped);for(auto x:output)assert(x.c0==17 && x.c1==19 && x.c2==23);}
        if(fault!=13 && fault!=21)fail_fence=false;
        C71RangeStats final{};const auto closed=c71_range_close(c,&final);
        if(fault==13 || fault==21 || fault==23) {
            assert(closed && final.cleanup_failed && joint_live);joint_live=0;
        }else assert(!closed && !joint_live && !final.arena_bytes);
        fail_fence=false;
    }
    C71RangeContext* c=nullptr;assert(!c71_range_create(0,16ULL<<20,256,joint_account,&c));
    Gate gate{2,0,0,0,{1,0,0}};GateRange range{0,1};Fp3 previous{},selector{},output[6]{};uint64_t token=0;
    assert(!c71_rms_index_begin(c,1,1,1,&gate,&range,&previous,&selector,&token));
    assert(!c71_rms_index_step(c,token,nullptr,0,output));assert(!stats(c).arena_bytes);
    C71RangeStats final{};assert(!c71_range_close(c,&final) && !joint_live);
    std::puts("C71_RMS_INDEX_OWNER {\"success\":2,\"terminal_rejections\":32,\"publication_after_free\":true,\"failed_fence_staging_retained\":true,\"gpu_execution\":false,\"credit\":false}");
}

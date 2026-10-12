#define main c71_other_statistic_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main

int main() {
    for(unsigned fault=0;fault<=25;++fault) {
        joint_limit=32ULL<<20;assert(!joint_live && !rms_registered);
        C71RangeContext* c=nullptr;assert(!c71_range_create(0,32ULL<<20,256,joint_account,&c));
        std::vector<uint8_t> source(30);Fp3 point[5]{},prefix[5]{},out[4];for(auto& x:out)x={17,19,23};
        uint64_t token=0;uint32_t checkpoint=77;
        if(fault==1)point[0].c0=P;
        if(fault==4)joint_limit=joint_live;
        if(fault==5)rms_map_support_fault=1;
        if(fault==6)rms_map_fault=1;
        if(fault==7)rms_map_fault=2;
        if(fault==8)upload_fail_after=0;
        if(fault==9)fail_fence=true;
        int status=c71_rms_statistic_begin(c,fault==2?0:3,5,source.data(),fault==3?29:30,point,5,
            fault==10?reinterpret_cast<uint64_t*>(point):&token,
            fault==11?reinterpret_cast<uint32_t*>(point):&checkpoint);
        joint_limit=32ULL<<20;rms_map_support_fault=0;if(fault!=24)rms_map_fault=0;upload_fail_after=-1;
        if(fault!=9)fail_fence=false;
        if(fault>=1 && fault<=11)assert(status && !token && checkpoint==77);
        else {
            assert(!status && token && checkpoint==0);
            if(fault==12)status=c71_rms_statistic_begin(c,3,5,source.data(),30,point,5,&token,&checkpoint);
            else if(fault==13)status=c71_range_release(c,token);
            else if(fault==14)status=c71_range_upload(c,token,point,120);
            else if(fault==25)status=c71_rms_statistic_coefficients(c,token,nullptr,0,reinterpret_cast<Fp3*>(source.data()));
            else {
                if(fault==16)prefix[0].c0=P;
                if(fault==17)upload_fail_after=0;
                if(fault==18)fail_launch=true;
                if(fault==19)download_fail_after=0;
                if(fault==20)fail_fence=true;
                status=c71_rms_statistic_coefficients(c,fault==15?token+1000:token,prefix,fault==16?1:0,out);
                upload_fail_after=download_fail_after=-1;fail_launch=false;if(fault!=20)fail_fence=false;
                if(fault>=15 && fault<=20)assert(status);
                else {
                    assert(!status);for(auto& x:out)x={17,19,23};
                    if(fault==21)status=c71_rms_statistic_terminal(c,token,prefix,5,out);
                    else if(fault==22) {
                        assert(!c71_rms_statistic_coefficients(c,token,prefix,1,out));
                        for(auto& x:out)x={17,19,23};
                        prefix[0]={1,0,0};
                        status=c71_rms_statistic_coefficients(c,token,prefix,2,out);
                    } else {
                        for(unsigned r=1;r<5;++r)assert(!c71_rms_statistic_coefficients(c,token,prefix,r,out));
                        for(auto& x:out)x={17,19,23};
                        if(fault==23)fail_free=true;
                        if(fault==24)rms_map_fault=3;
                        status=c71_rms_statistic_terminal(c,token,prefix,5,out);fail_free=false;
                        if(!fault) {
                            assert(!status && !stats(c).arena_bytes && stats(c).allocations==stats(c).releases);
                            assert(stats(c).host_owner_bytes==42504 && !rms_registered);
                            std::vector<uint8_t> singleton(2);
                            assert(!c71_rms_statistic_begin(c,1,1,singleton.data(),2,nullptr,0,&token,&checkpoint));
                            assert(!checkpoint && !c71_rms_statistic_terminal(c,token,nullptr,0,out));
                        }
                    }
                    if(fault)assert(status);
                }
            }
        }
        if(fault) {assert(stats(c).stopped);for(auto x:out)assert(x.c0==17 && x.c1==19 && x.c2==23);}
        C71RangeStats final{};const int closed=c71_range_close(c,&final);
        if(fault==9 || fault==20 || fault==23 || fault==24) {
            assert(closed && final.cleanup_failed && joint_live);joint_live=0;rms_registered=nullptr;
        } else assert(!closed && !joint_live && !rms_registered && !final.arena_bytes);
        fail_fence=false;rms_map_fault=0;
    }
    std::puts("C71_RMS_STATISTIC_OWNER {\"success\":1,\"terminal_rejections\":25,\"singleton\":true,\"owned_until_fence\":true,\"gpu_execution\":false,\"credit\":false}");
}

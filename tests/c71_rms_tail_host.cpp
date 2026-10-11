#define main c71_other_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main

int main() {
    using namespace c71_rms_prefix;
    for(unsigned fault=0;fault<=22;++fault) {
        joint_limit=16ULL<<20;assert(!joint_live && !rms_registered);
        C71RangeContext* c=nullptr;assert(!c71_range_create(0,16ULL<<20,256,joint_account,&c));
        std::vector<uint8_t> payload(280,42);SourceShape source_shape{280,64,64,1,1,1,0};
        SourceNorm norm{0,128,152,64,2,16,4,0};SourceTile tile{0,64,0,0,0,16,0,0};uint64_t source=0;
        assert(!c71_rms_source_begin(c,source_shape,payload.data(),&norm,&tile,&source));
        Shape shape{1,8,256,2,1,2,1,1,1,1};Program program{4,5,1,0,0,0,1};Node node{0,4,2,3};
        uint32_t bounds[]={0,1},output=4;Gate gate{0,0,0,0,{1,0,0}};
        Fp3 point[6]{};GateRange range{0,1};uint16_t mask=0xffff;Section section{0,4};uint64_t prefix=0;
        assert(!c71_rms_prefix_begin(c,shape,&program,&node,bounds,&output,&gate,point+4,&range,&mask,&section,&prefix));
        uint16_t mask_id=0;assert(!c71_rms_prefix_window_from_source(c,prefix,source,0,4,&mask_id));
        Fp3 moments[272],coefficients[4],terminal[18];
        for(auto& x:moments)x={17,19,23};
        for(auto& x:coefficients)x={17,19,23};
        for(auto& x:terminal)x={17,19,23};
        if(fault==2)point[0].c0=P;
        if(fault==4)joint_limit=joint_live;
        if(fault==22)point[4].c0=1;
        int status=c71_rms_prefix_finish_tail(c,prefix,fault==3?source+1000:source,point,fault==1?5:6,moments,272);
        joint_limit=16ULL<<20;
        if((fault>=1 && fault<=4) || fault==22)assert(status);
        else {
            assert(!status);
            for(auto x:moments)assert(!x.c0 && !x.c1 && !x.c2);
            Fp3 challenges[5]{};
            if(fault==5)fail_launch=true;
            if(fault==6)fail_memset=true;
            if(fault==7)upload_fail_after=0;
            if(fault==8 || fault==19)fail_fence=true;
            if(fault==9)corrupt=true;
            if(fault==11)challenges[0].c0=P;
            if(fault==18)download_fail_after=0;
            if(fault==20)joint_limit=joint_live;
            if(fault==14)status=c71_rms_prefix_window_from_source(c,prefix,source,0,4,&mask_id);
            else if(fault==15)status=c71_rms_source_retire(c,source);
            else if(fault==16)status=c71_rms_prefix_finish(c,prefix,moments,272);
            else status=c71_rms_tail_round(c,fault==21?prefix+1000:prefix,challenges,fault==10?5:4,
                coefficients,nullptr,fault==13?18:0);
            fail_launch=false;fail_memset=false;upload_fail_after=-1;corrupt=false;download_fail_after=-1;joint_limit=16ULL<<20;
            if(fault!=19)fail_fence=false;
            if(fault && fault!=12 && fault!=17)assert(status);
            else {
                assert(!status);for(auto x:coefficients)assert(!x.c0 && !x.c1 && !x.c2);
                for(auto& x:coefficients)x={17,19,23};
                if(fault==17)fail_free=true;
                status=c71_rms_tail_round(c,prefix,challenges,5,fault==12?terminal:coefficients,terminal,18);
                fail_free=false;
                if(fault)assert(status);
                else {
                    assert(!status);for(auto x:terminal)assert(!x.c0 && !x.c1 && !x.c2);
                    assert(!c71_rms_source_retire(c,source));assert(!stats(c).arena_bytes);
                    assert(stats(c).host_owner_bytes==42496);
                }
            }
        }
        if(fault) {
            assert(stats(c).stopped);
            for(auto x:coefficients)assert(x.c0==17 && x.c1==19 && x.c2==23);
            for(auto x:terminal)assert(x.c0==17 && x.c1==19 && x.c2==23);
        }
        const auto unregistered=rms_unregisters;C71RangeStats final{};const auto closed=c71_range_close(c,&final);
        if(fault==17 || fault==19) {
            assert(closed && final.cleanup_failed && joint_live);
            if(fault==19)assert(rms_unregisters==unregistered && rms_registered);
            joint_live=0;rms_registered=nullptr;
        }else assert(!closed && !joint_live && !rms_registered && !final.arena_bytes);
        fail_fence=false;
    }
    std::puts("C71_RMS_CELL_TAIL_OWNER {\"success\":1,\"terminal_rejections\":22,\"publication_after_free\":true,\"failed_fence_staging_retained\":true,\"gpu_execution\":false,\"credit\":false}");
}

#define main c71_other_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main
#include <unistd.h>

int main() {
    using namespace c71_rms_prefix;
    for(unsigned fault=0;fault<=26;++fault) {
        joint_limit=16ULL<<20;assert(!joint_live && !rms_registered);
        C71RangeContext* c=nullptr;assert(!c71_range_create(0,16ULL<<20,256,joint_account,&c));
        std::vector<uint8_t> payload(140,42);
        SourceShape shape{140,32,32,1,1,1,0};
        SourceNorm norm{0,64,76,32,2,16,2,0};
        SourceTile tile{0,32,0,0,0,16,0,0};uint64_t source=0;
        if(fault==1)shape.bytes=139;
        if(fault==2)norm.cells=31;
        if(fault==3)norm.statistic=63;
        if(fault==4)norm.output=75;
        if(fault==5)norm.pbytes=3;
        if(fault==6)tile.end=31;
        if(fault==7)tile.program=1;
        if(fault==8)tile.first=1;
        if(fault==9)shape.padded=64;
        if(fault>=10 && fault<=12)rms_map_support_fault=fault-9;
        if(fault==13)rms_map_fault=1;
        if(fault==14)rms_map_fault=2;
        if(fault==15)rms_map_fault=4;
        if(fault==16)upload_fail_after=0;
        if(fault==17)fail_fence=true;
        if(fault==24)joint_limit=joint_live;
        if(fault==25)joint_limit=joint_live+8190;
        const auto address=reinterpret_cast<uintptr_t>(payload.data());
        const auto page=uint64_t(sysconf(_SC_PAGESIZE));
        const auto slack=address%page+(page-(address+payload.size())%page)%page;
        if(fault==25)joint_limit=joint_live+slack;
        int status=c71_rms_source_begin(c,shape,payload.data(),&norm,&tile,&source);
        rms_map_fault=rms_map_support_fault=0;upload_fail_after=-1;fail_fence=false;joint_limit=16ULL<<20;
        if((fault>=1 && fault<=17) || fault==24 || fault==25)assert(status && !source);
        else {
            assert(!status && source && stats(c).allocations==1);
            assert(stats(c).host_owner_bytes==42384+slack+288 && stats(c).h2d_bytes==288);
            if(fault>=19 && fault<=22) {
                Shape prefix_shape{1,8,256,1,1,2,1,1,1,1};
                Program program{4,5,1,0,0,0,1};Node node{0,4,2,3};
                uint32_t bounds[]={0,1},output=4;Gate gate{0,0,0,0,{1,0,0}};
                Fp3 point{};GateRange range{0,1};uint16_t mask=0xffff;Section section{0,2};uint64_t prefix=0;
                assert(!c71_rms_prefix_begin(c,prefix_shape,&program,&node,bounds,&output,&gate,&point,&range,&mask,&section,&prefix));
                uint16_t mask_id=fault==20?0xffff:0;
                if(fault==19)status=c71_rms_source_retire(c,source);
                else status=c71_rms_prefix_window_from_source(c,prefix,fault==21?source+1000:source,
                    fault==22?1:0,2,&mask_id);
                assert(status && stats(c).d2h_bytes==0);
            } else {
                if(fault==18)rms_map_fault=3;
                if(fault==23)fail_free=true;
                if(fault==26)fail_fence=true;
                status=c71_rms_source_retire(c,source);
                fail_free=false;
                if(fault)assert(status);
                else {
                    assert(!status && !stats(c).arena_bytes && !rms_registered);
                    assert(stats(c).host_owner_bytes==42384 && !stats(c).d2h_bytes);
                }
            }
        }
        const auto unregistered=rms_unregisters;
        if(fault)assert(stats(c).stopped);
        C71RangeStats final{};const auto closed=c71_range_close(c,&final);
        if(fault==18 || fault==23 || fault==26) {
            assert(closed && final.cleanup_failed && joint_live);
            if(fault==18 || fault==26)assert(rms_unregisters==unregistered && rms_registered);
            // The negative fixture has a dead owner. Simulated leaked debt is
            // reset only for the next independent case, never for continuation.
            joint_live=0;rms_registered=nullptr;
        } else assert(!closed && !joint_live && !rms_registered && !final.arena_bytes);
        rms_map_fault=0;fail_fence=false;
    }
    std::puts("C71_RMS_SOURCE_OWNER {\"success\":1,\"terminal_rejections\":26,\"no_unregister_retry\":true,\"no_frame_download\":true,\"gpu_execution\":false,\"credit\":false}");
}

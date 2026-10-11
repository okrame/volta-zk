#define main c71_other_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main

int main() {
    using namespace c71_rms_prefix;
    for(unsigned fault=0;fault<24;++fault) {
        joint_limit=16ULL<<20; assert(!joint_live);
        C71RangeContext* c=nullptr; assert(!c71_range_create(0,16ULL<<20,256,joint_account,&c));
        Shape shape{1,8,256,9,1,2,1,1,1,2};
        Program program{4,5,1,0,0,0,1}; Node node{0,4,2,3};
        uint32_t boundaries[]={0,1},output=4; Gate gate{0,0,0,0,{1,0,0}};
        Fp3 point[9]{}; GateRange range{0,1}; uint16_t mask=0xffff;
        Section sections[]={{2,5},{7,9}}; uint64_t token=0;
        std::vector<uint8_t> frames(16*256*12,42);
        std::vector<uint16_t> assigned(16*256,0xffff); uint16_t mask_id=0;
        Fp3 moments[272]; for(auto& value:moments)value={17,19,23};
        if(fault==1)shape.width=3;
        if(fault==2)program.slots=3;
        if(fault==3)node.x=4;
        if(fault==4)boundaries[1]=2;
        if(fault==5)output=5;
        if(fault==6)mask=0;
        if(fault==7)sections[1].first=4;
        if(fault==8)gate.weight.c1=P;
        if(fault==9)upload_fail_after=1;
        if(fault==21)fail_fence=true;
        int status=c71_rms_prefix_begin(c,shape,&program,&node,boundaries,&output,&gate,point,&range,&mask,sections,&token);
        upload_fail_after=-1;
        if((fault>=1 && fault<=9) || fault==21)assert(status && !token);
        else {
            assert(!status && token && stats(c).allocations==7 && stats(c).host_owner_bytes==44304);
            for(unsigned row=0;row<16;++row)for(unsigned k=0;k<3;++k)assigned[row*256+k]=0;
            if(fault==10)assigned[255]=0;
            if(fault==11)mask_id=0xffff;
            if(fault==12)assigned[1]=0xffff;
            if(fault==13)fail_launch=true;
            if(fault==14)upload_fail_after=1;
            if(fault==23)upload_fail_after=2; // New owned window-plan H2D after both frame uploads.
            if(fault==15 || fault==22)fail_fence=true;
            status=c71_rms_prefix_window(c,token,fault==16?3:2,3,frames.data(),assigned.data(),&mask_id);
            fail_launch=false;upload_fail_after=-1;
            if(fault!=22)fail_fence=false;
            if((fault>=10 && fault<=16) || fault==22 || fault==23)assert(status);
            else {
                assert(!status);
                if(fault!=17) {
                    assigned.assign(16*256,0xffff);
                    for(unsigned row=0;row<16;++row)for(unsigned k=0;k<2;++k)assigned[row*256+k]=0;
                    assert(!c71_rms_prefix_window(c,token,7,2,frames.data(),assigned.data(),&mask_id));
                }
                if(fault==18)download_fail_after=0;
                if(fault==19)fail_free=true;
                if(fault==20)fail_fence=true;
                status=c71_rms_prefix_finish(c,token,moments,272);
                fail_free=false;download_fail_after=-1;
                if(fault==20)fail_fence=false;
                if(fault>=17)assert(status);
                else {
                    assert(!status && !stats(c).arena_bytes && stats(c).releases==7);
                    assert(stats(c).host_owner_bytes==42496 && stats(c).h2d_bytes==115032);
                    assert(stats(c).zeroed_bytes==14720 && stats(c).d2h_bytes==6528 && stats(c).launches==12);
                    for(auto value:moments)assert(value.c0==0 && value.c1==0 && value.c2==0);
                }
            }
        }
        if(fault) {
            assert(stats(c).stopped);
            for(auto value:moments)assert(value.c0==17 && value.c1==19 && value.c2==23);
        }
        C71RangeStats final{};
        const auto closed=c71_range_close(c,&final);
        if(fault==19 || fault==21 || fault==22) {
            assert(closed && final.cleanup_failed && joint_live);
            if(fault==19)assert(final.live_capacity_bytes);
            joint_live=0;
        }
        else assert(!closed && !joint_live && !final.live_capacity_bytes);
        fail_fence=false;
    }
    assert(allocations==frees);
    std::puts("C71_RMS_OWNER {\"success\":1,\"terminal_rejections\":23,\"publication_after_free\":true,\"gpu_execution\":false,\"credit\":false}");
}

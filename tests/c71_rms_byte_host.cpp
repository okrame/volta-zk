#define main c71_other_owner_checks
#include "c71_range_runtime_host.cpp"
#undef main

int main() {
    using namespace c71_rms_prefix;
    for(unsigned fault=0;fault<=30;++fault) {
        joint_limit=64ULL<<20;assert(!joint_live && !rms_registered);
        C71RangeContext* c=nullptr;assert(!c71_range_create(0,64ULL<<20,256,joint_account,&c));
        std::vector<uint8_t> payload(280,42);SourceShape source_shape{280,64,64,1,1,1,0};
        SourceNorm norm{0,128,152,64,2,16,4,0};SourceTile tile{0,64,0,0,0,16,0,0};uint64_t source=0;
        assert(!c71_rms_source_begin(c,source_shape,payload.data(),&norm,&tile,&source));
        std::vector<Fp3> coefficients(16*256),features(16*257);
        c71_rms_byte::FeatureRange ranges[16];for(unsigned i=0;i<16;++i)ranges[i]={i,1};
        Fp3 point[17]{},prefix[17]{},out[4];for(auto& x:out)x={17,19,23};uint64_t token=0;uint32_t checkpoint=0;
        if(fault==3)coefficients[0].c0=P;
        if(fault==4)joint_limit=joint_live;
        if(fault==5)upload_fail_after=0;
        if(fault==6)fail_fence=true;
        int status=c71_rms_byte_begin(c,fault==7?source+1000:source,fault==1?5:6,fault==2?9:10,
            coefficients.data(),fault==8?reinterpret_cast<uint64_t*>(coefficients.data()):&token);
        joint_limit=64ULL<<20;upload_fail_after=-1;if(fault!=6)fail_fence=false;
        if(fault>=1 && fault<=8)assert(status && !token);
        else {
            assert(!status && token);
            if(fault==9)status=c71_rms_byte_begin(c,source,6,10,coefficients.data(),&token);
            else if(fault==10)status=c71_rms_source_retire(c,source);
            else if(fault==11)status=c71_range_release(c,token);
            else if(fault==12)status=c71_range_upload(c,token,coefficients.data(),16*256*24);
            else {
                if(fault==15)ranges[0].first=1;
                if(fault==16)ranges[0].count=5;
                if(fault==17)point[0].c0=P;
                if(fault==19)features[0].c0=P;
                if(fault==20)upload_fail_after=0;
                if(fault==21)fail_fence=true;
                status=c71_rms_byte_layer(c,token,fault==13?1:0,point,fault==14?9:10,
                    fault==18?Fp3{P,0,0}:Fp3{},ranges,features.data(),16,
                    fault==30?reinterpret_cast<uint32_t*>(point):&checkpoint);
                upload_fail_after=-1;if(fault!=21)fail_fence=false;
                if((fault>=13 && fault<=21) || fault==30)assert(status);
                else {
                    assert(!status);
                    if(fault==24)fail_launch=true;
                    if(fault==25)upload_fail_after=0;
                    if(fault==26)download_fail_after=0;
                    if(fault==27)fail_fence=true;
                    if(fault==28)status=c71_rms_byte_terminal(c,token,point,10,out);
                    else status=c71_rms_byte_coefficients(c,token,prefix,fault==22?1:0,out);
                    fail_launch=false;upload_fail_after=download_fail_after=-1;if(fault!=27)fail_fence=false;
                    if(fault>=22 && fault<=28 && fault!=23)assert(status);
                    else {
                        assert(!status);
                        for(auto& x:out)x={17,19,23};
                        if(fault==23) {
                            assert(!c71_rms_byte_coefficients(c,token,prefix,1,out));
                            for(auto& x:out)x={17,19,23};prefix[0]={1,0,0};
                            status=c71_rms_byte_coefficients(c,token,prefix,2,out);assert(status);
                        } else {
                            for(unsigned round=1;round<10;++round)assert(!c71_rms_byte_coefficients(c,token,prefix,round,out));
                            for(auto& x:out)x={17,19,23};if(fault==29)fail_free=true;
                            status=c71_rms_byte_terminal(c,token,prefix,10,out);fail_free=false;
                            if(fault==29)assert(status);
                            else {
                                assert(!status);
                                for(unsigned layer=1;layer<8;++layer) {
                                    assert(!c71_rms_byte_layer(c,token,layer,point,10+layer,Fp3{},ranges,features.data(),16,&checkpoint));
                                    for(unsigned r=0;r<10+layer;++r)assert(!c71_rms_byte_coefficients(c,token,prefix,r,out));
                                    assert(!c71_rms_byte_terminal(c,token,prefix,10+layer,out));
                                }
                                assert(!c71_rms_source_retire(c,source));assert(!stats(c).arena_bytes);
                                assert(stats(c).allocations==stats(c).releases && stats(c).host_owner_bytes==42504);
                            }
                        }
                    }
                }
            }
        }
        if(fault) {
            assert(stats(c).stopped);
            for(auto x:out)assert(x.c0==17 && x.c1==19 && x.c2==23);
        }
        C71RangeStats final{};const int closed=c71_range_close(c,&final);
        if(fault==6 || fault==21 || fault==27 || fault==29) {
            assert(closed && final.cleanup_failed && joint_live);joint_live=0;rms_registered=nullptr;
        } else assert(!closed && !joint_live && !rms_registered && !final.arena_bytes);
        fail_fence=false;
    }
    std::puts("C71_RMS_BYTE_OWNER {\"success\":1,\"terminal_rejections\":30,\"all_eight_layers\":true,\"source_retire_blocked\":true,\"failed_fence_staging_retained\":true,\"gpu_execution\":false,\"credit\":false}");
}
